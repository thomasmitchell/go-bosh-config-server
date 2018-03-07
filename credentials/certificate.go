package credentials

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/thomasmmitchell/go-bosh-config-server/credentials/internal"
)

//Only works with RSA keys and certs signed by RSA keys
type certificate struct {
	ca          []byte
	certificate []byte
	privateKey  []byte
}

type certificateParams struct {
	CommonName       string   `json:"common_name"`
	AlternativeNames []string `json:"alternative_names"`
	Organization     string   `json:"organization"`
	OrganizationUnit string   `json:"organization_unit"`
	Locality         string   `json:"locality"`
	State            string   `json:"state"`
	Country          string   `json:"country"`
	//Can be combination of digital_signature, non_repudiation, key_encipherment,
	//data_encipherment, key_agreement, key_cert_sign, crl_sign, encipher_only,
	//decipher_only
	KeyUsage []string `json:"key_usage"`
	//Can be combination of client_auth, server_auth, code_signing,
	//email_protection, timestamping
	ExtendedKeyUsage []string `json:"extended_key_usage"`
	//KeyLength can be an int or a string
	KeyLength internal.IntOrString `json:"key_length"`
	Duration  internal.IntOrString `json:"duration"`
	//This is the path to where in the backend the CA is stored
	CA       string `json:"ca"`
	IsCA     bool   `json:"is_ca"`
	SelfSign bool   `json:"self_sign"`
}

type certificateValue struct {
	//Must set one of, but not both of, CA and CAName
	CA string `json:"ca"`
	//Path in backend to CA that signed this
	CAName      string `json:"ca_name,omitempty"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

var keyUsageLookup = map[string]x509.KeyUsage{
	"digital_signature":  x509.KeyUsageDigitalSignature,
	"non_repudiation":    x509.KeyUsageContentCommitment,
	"content_commitment": x509.KeyUsageContentCommitment,
	"key_encipherment":   x509.KeyUsageKeyEncipherment,
	"data_encipherment":  x509.KeyUsageDataEncipherment,
	"key_agreement":      x509.KeyUsageKeyAgreement,
	"key_cert_sign":      x509.KeyUsageCertSign,
	"crl_sign":           x509.KeyUsageCRLSign,
	"encipher_only":      x509.KeyUsageEncipherOnly,
	"decipher_only":      x509.KeyUsageDecipherOnly,
}

var extendedKeyUsageLookup = map[string]x509.ExtKeyUsage{
	"client_auth":      x509.ExtKeyUsageClientAuth,
	"server_auth":      x509.ExtKeyUsageServerAuth,
	"code_signing":     x509.ExtKeyUsageCodeSigning,
	"email_protection": x509.ExtKeyUsageEmailProtection,
	"timestamping":     x509.ExtKeyUsageTimeStamping,
}

func (c *certificate) ParamType() interface{} {
	return certificateParams{
		KeyLength: 2048,
		Duration:  365,
	}
}

func (c *certificate) ValueType() interface{} {
	return certificateValue{}
}

func verifyGenerationParameters(input *certificateParams) error {
	//First, let's validate the incoming parameters
	if err := verifySubject(input); err != nil {
		return err
	}

	if err := verifyParentExists(input); err != nil {
		return err
	}

	if input.Duration < 0 {
		return newErrInvalidParams("duration must be non-negative")
	}

	return nil
}

func verifySubject(input *certificateParams) (err error) {
	if input.CommonName == "" && input.Organization == "" &&
		input.OrganizationUnit == "" && input.Locality == "" &&
		input.State == "" && input.Country == "" {
		err = newErrInvalidParams("In parameters, must define at least one of " +
			"`common_name', `organization', `organization_unit', `locality', " +
			"`state', or `country'")
	}
	return
}

func verifyParentExists(input *certificateParams) (err error) {
	if input.CA == "" && !input.IsCA && !input.SelfSign {
		err = newErrInvalidParams("In parameters, must define at least one of " +
			"`ca', `is_ca', or `self_sign'")
	}

	if input.IsCA && input.CA == "" {
		input.SelfSign = true
	}
	return
}

func translateKeyUsage(input *certificateParams) (keyUsage x509.KeyUsage, err error) {
	var found bool

	for _, usage := range input.KeyUsage {
		var thisKeyUsage x509.KeyUsage
		if thisKeyUsage, found = keyUsageLookup[usage]; !found {
			err = newErrInvalidParams("key_usage must be an array consisting only " +
				"of values `digital_signature', `non_repudiation', `key_encipherment', " +
				"`data_encipherment', `key_agreement', `key_cert_sign', `crl_sign', " +
				"`encipher_only', or `decipher_only'")
			break
		}
		keyUsage = keyUsage | thisKeyUsage
	}

	return
}

func translateExtendedKeyUsage(input *certificateParams) (extendedKeyUsage []x509.ExtKeyUsage, err error) {
	var found bool

	for _, extUsage := range input.ExtendedKeyUsage {
		var thisExtKeyUsage x509.ExtKeyUsage
		if thisExtKeyUsage, found = extendedKeyUsageLookup[extUsage]; !found {
			err = newErrInvalidParams("extended_key_usage must be an array consisting only " +
				"of values `client_auth', `server_auth', `code_signing', " +
				"`email_protection', or `timestamping'")
			break
		}
		extendedKeyUsage = append(extendedKeyUsage, thisExtKeyUsage)
	}
	return
}

func constructSubject(input *certificateParams) pkix.Name {
	return pkix.Name{
		CommonName:         input.CommonName,
		Organization:       []string{input.Organization},
		OrganizationalUnit: []string{input.OrganizationUnit},
		Locality:           []string{input.Locality},
		Province:           []string{input.State},
		Country:            []string{input.Country},
	}
}

func sortAlternativeNames(altnames []string) (dnses, emails []string, ips []net.IP, err error) {
	for _, name := range altnames {
		if strings.ContainsRune(name, '@') {
			emails = append(emails, name)
			continue
		} else if ip := net.ParseIP(name); ip != nil {
			//This check needs to go before the URI check because an IPv6 address has colons
			ips = append(ips, ip)
			continue
		} else if strings.ContainsRune(name, ':') {
			err = newErrInvalidParams("Subject alternative name was not valid")
			return
		}

		//If its not an email, or IP, assume its a hostname
		dnses = append(dnses, name)
	}

	return
}

func (c *certificate) Generate(in interface{}) error {
	input := in.(certificateParams)

	if err := verifyGenerationParameters(&input); err != nil {
		return err
	}

	//Can't verify keyusage, extKeyUsage, and keyLength with the others
	// because we translate their values to something we can use
	keyUsage, err := translateKeyUsage(&input)
	if err != nil {
		return err
	}

	extendedKeyUsage, err := translateExtendedKeyUsage(&input)
	if err != nil {
		return err
	}

	dnses, emails, ips, err := sortAlternativeNames(input.AlternativeNames)
	if err != nil {
		return err
	}

	rsaGenerator := rsaPair{}
	err = rsaGenerator.Generate(rsaPairParams{KeyLength: input.KeyLength})
	if err != nil {
		//the RSA object should already output errors in the format we want
		return err
	}

	c.privateKey = []byte(rsaGenerator.ValueOut().(rsaPairValue).PrivateKey)

	rsaPEMBlock, _ := pem.Decode(c.privateKey)
	if rsaPEMBlock == nil {
		return fmt.Errorf("Could not decode generated private key from PEM")
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(rsaPEMBlock.Bytes)
	if err != nil {
		return err
	}

	//Can either be a CA or self-signed
	templateCert := x509.Certificate{
		Subject:        constructSubject(&input),
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extendedKeyUsage,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 24 * time.Duration(input.Duration)),
		IsCA:           input.IsCA,
		DNSNames:       dnses,
		EmailAddresses: emails,
		IPAddresses:    ips,
	}

	signingCert := templateCert
	signingKey := rsaKey
	if !input.SelfSign {
		//TODO: Once the backend API is a thing, we'll use that.
		// Just make our own temp CA cert for now
		signingCert = x509.Certificate{
			SignatureAlgorithm: x509.SHA512WithRSA,
			PublicKeyAlgorithm: x509.RSA,
			Subject: pkix.Name{
				CommonName: "ca.example.com",
			},
			DNSNames: []string{"ca.example.com"},
			IsCA:     true,
			BasicConstraintsValid: true,
			MaxPathLen:            1,
			SerialNumber:          big.NewInt(1),
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * time.Duration(input.Duration)),
		}

		signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		caCertDER, err := x509.CreateCertificate(rand.Reader, &signingCert, &signingCert, signingKey.Public, signingKey)
		if err != nil {
			return err
		}

		c.ca = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCertDER,
		})
	}

	newCertDER, err := x509.CreateCertificate(rand.Reader, &templateCert, &signingCert, rsaKey.PublicKey, signingKey)
	if err != nil {
		//If this error procs, I don't really know what went wrong...
		return err
	}

	c.certificate = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCertDER,
	})

	return nil
}

//BackendIn requires "certificate", and "private_key". "ca" should be present
//for a cert that is not self-signed
func (c *certificate) BackendIn(input map[string]string) {
	c.ca = []byte(input["ca"])
	c.certificate = []byte(input["certificate"])
	c.privateKey = []byte(input["private_key"])
}

func (c *certificate) BackendOut() map[string]string {
	ret := map[string]string{
		"certificate": string(c.certificate),
		"private_key": string(c.privateKey),
	}
	if len(c.ca) > 0 {
		ret["ca"] = string(c.ca)
	}

	return ret
}

func (c *certificate) ValueIn(in interface{}) {
	input := in.(certificateValue)
	//TODO: Handle other CAName for backend paths
	c.ca = []byte(input.CA)
	c.certificate = []byte(input.Certificate)
	c.privateKey = []byte(input.PrivateKey)
}

func (c *certificate) ValueOut() interface{} {
	ret := certificateValue{
		CA:          string(c.ca),
		Certificate: string(c.certificate),
		PrivateKey:  string(c.privateKey),
	}

	return ret
}

func (c *certificate) Validate() error {
	newErrNotPEM := func(key string) error {
		return newErrCredUnusable(fmt.Sprintf("`%s' is not in PEM format", key))
	}

	if len(c.ca)+len(c.certificate)+len(c.privateKey) == 0 {
		return newErrCredUnusable("must set at least one of `certificate', `ca', or `private_key'")
	}

	var pemBlock *pem.Block
	var err error

	var caCert *x509.Certificate
	if len(c.ca) > 0 {
		pemBlock, _ = pem.Decode(c.ca)
		if pemBlock == nil {
			return newErrNotPEM("ca")
		}

		if caCert, err = x509.ParseCertificate(pemBlock.Bytes); err != nil {
			return newErrCredUnusable("`ca' is not a valid certificate")
		}

		if caCert.PublicKeyAlgorithm != x509.RSA {
			return newErrCredUnusable("`ca' is not signed by an RSA key")
		}
	}

	var certCert *x509.Certificate
	if len(c.certificate) > 0 {
		pemBlock, _ = pem.Decode(c.certificate)
		if pemBlock == nil {
			return newErrNotPEM("certificate")
		}
		if certCert, err = x509.ParseCertificate(pemBlock.Bytes); err != nil {
			return newErrCredUnusable("`certificate' is not a valid certificate")
		}
		if certCert.PublicKeyAlgorithm != x509.RSA {
			return newErrCredUnusable("`certificate' is not signed by an RSA key")
		}
	}

	var privateKey *rsa.PrivateKey
	if len(c.privateKey) > 0 {
		pemBlock, _ = pem.Decode(c.privateKey)
		if pemBlock == nil {
			return newErrNotPEM("private_key")
		}
		if privateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err != nil {
			return newErrCredUnusable("`private_key' is not a valid RSA Private Key")
		}
	}

	if len(c.ca) > 0 && len(c.certificate) > 0 {
		err = certCert.CheckSignatureFrom(caCert)
		if err != nil {
			return newErrCredUnusable("`certificate' is not signed by `ca'")
		}
	}

	if len(c.certificate) > 0 && len(c.privateKey) > 0 {
		pubKey := certCert.PublicKey.(rsa.PublicKey)
		if pubKey.N != privateKey.N {
			return newErrCredUnusable("`certificate' is not signed by `private_key'")
		}
	}

	return nil
}
