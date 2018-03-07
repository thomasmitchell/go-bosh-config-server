package credentials

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/thomasmmitchell/go-bosh-config-server/credentials/internal"
)

type rsaPair struct {
	privateKey []byte
	publicKey  []byte
}

type rsaPairParams struct {
	KeyLength internal.IntOrString `json:"key_length"`
}

type rsaPairValue struct {
	PublicKey string `json:"public_key"`
	//PrivateKey is optional on output
	PrivateKey string `json:"private_key"`
}

var keyLengthLookup = map[internal.IntOrString]int{
	1024: 1024,
	2048: 2048,
	4096: 4096,
}

func (r *rsaPair) ParamType() interface{} {
	return rsaPairParams{KeyLength: internal.IntOrString(2048)}
}

func (r *rsaPair) ValueType() interface{} {
	return rsaPairValue{}
}

func (r *rsaPair) Generate(in interface{}) error {
	input := in.(rsaPairParams)

	keyLength, found := keyLengthLookup[input.KeyLength]
	if !found {
		return newErrInvalidParams("key_length must be one of `1024', `2048' or `4096'")
	}

	//Finally, we begin. Let's make the key with the requested length
	rsaKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}

	r.privateKey = x509.MarshalPKCS1PrivateKey(rsaKey)
	key, err := x509.ParsePKCS1PrivateKey(r.privateKey)
	if err != nil {
		panic("RSA Key on ValueOut was bogus")
	}

	r.publicKey = x509.MarshalPKCS1PublicKey(key.Public().(*rsa.PublicKey))

	return nil
}

//BackendIn requires 'public_key'. 'private_key' is optional
func (r *rsaPair) BackendIn(input map[string]string) {
	r.privateKey = []byte(input["private_key"])
	r.publicKey = []byte(input["public_key"])
}

func (r *rsaPair) BackendOut() map[string]string {
	ret := map[string]string{}
	if len(r.privateKey) > 0 {
		ret["private_key"] = string(r.privateKey)
	}

	if len(r.publicKey) > 0 {
		ret["public_key"] = string(r.publicKey)
	}

	return ret
}

func (r *rsaPair) ValueIn(in interface{}) {
	input := in.(rsaPairValue)
	r.privateKey = []byte(input.PrivateKey)
	r.publicKey = []byte(input.PublicKey)
}

func (r *rsaPair) ValueOut() interface{} {
	return rsaPairValue{
		PublicKey:  string(r.publicKey),
		PrivateKey: string(r.privateKey),
	}
}

func (r *rsaPair) Validate() error {
	if len(r.privateKey)+len(r.publicKey) > 0 {
		return newErrCredUnusable("Must define at least one of `public_key' or `private_key'")
	}

	var err error
	var privKey *rsa.PrivateKey

	if len(r.privateKey) > 0 {
		privatePEMBlock, _ := pem.Decode(r.privateKey)
		if privatePEMBlock == nil {
			return newErrCredUnusable("Private key was not in PEM format")
		}

		privKey, err = x509.ParsePKCS1PrivateKey(privatePEMBlock.Bytes)
		if err != nil {
			return newErrCredUnusable(fmt.Sprintf("Could not parse private key: %s", err))
		}
	}

	var pubKey *rsa.PublicKey
	if len(r.publicKey) > 0 {
		publicPEMBlock, _ := pem.Decode(r.publicKey)
		if publicPEMBlock == nil {
			return newErrCredUnusable("Public key was not in PEM format")
		}

		pubKey, err = x509.ParsePKCS1PublicKey(publicPEMBlock.Bytes)
		if err != nil {
			return newErrCredUnusable(fmt.Sprintf("Could not parse public key: %s", err))
		}
	} else {
		//Infer public key from private key
		//Private key must be present because of earlier check
		r.publicKey = x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
		pubKey = &privKey.PublicKey
	}

	if len(r.privateKey) > 0 && len(r.publicKey) > 0 {
		if pubKey.N != privKey.N {
			return newErrCredUnusable(fmt.Sprintf("Public key does not match private key"))
		}
	}

	return nil
}
