package credentials

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/thomasmmitchell/go-bosh-config-server/credentials/internal"
	"golang.org/x/crypto/ssh"
)

type sshPair struct {
	privateKey []byte
	publicKey  []byte
}

type sshPairParams struct {
	KeyLength  internal.IntOrString `json:"key_length"`
	SSHComment string               `json:"ssh_comment"`
}

type sshPairValue struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func (s *sshPair) ParamType() interface{} {
	return sshPairParams{KeyLength: 2048}
}

func (s *sshPair) ValueType() interface{} {
	return sshPairValue{}
}

func (s *sshPair) Generate(in interface{}) error {
	input := in.(sshPairParams)

	rsaGenerator := rsaPair{}
	err := rsaGenerator.Generate(rsaPairParams{KeyLength: input.KeyLength})
	if err != nil {
		//the RSA object should already output errors in the format we want
		return err
	}

	s.privateKey = []byte(rsaGenerator.ValueOut().(rsaPairValue).PrivateKey)

	privKeyPEMBlock, _ := pem.Decode(s.privateKey)
	if privKeyPEMBlock == nil {
		return fmt.Errorf("Generated a non PEM-encoded RSA key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privKeyPEMBlock.Bytes)
	if err != nil {
		return fmt.Errorf("Generated a poorly formatted RSA key")
	}

	sshPubKey, err := ssh.NewPublicKey(privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("Could not translate RSA pubkey into SSH")
	}

	s.publicKey = ssh.MarshalAuthorizedKey(sshPubKey)
	if len(input.SSHComment) > 0 {
		s.publicKey = []byte(fmt.Sprintf("%s %s", s.publicKey, input.SSHComment))
	}

	return nil
}

//BackendIn requires 'public_key'. 'private_key' is optional
func (s *sshPair) BackendIn(input map[string]string) {
	s.privateKey = []byte(input["private_key"])
	s.publicKey = []byte(input["public_key"])
}

func (s *sshPair) BackendOut() map[string]string {
	ret := map[string]string{}
	if len(s.privateKey) > 0 {
		ret["private_key"] = string(s.privateKey)
	}

	if len(s.publicKey) > 0 {
		ret["public_key"] = string(s.publicKey)
	}

	return ret
}

func (s *sshPair) ValueIn(in interface{}) {
	input := in.(sshPairValue)
	s.privateKey = []byte(input.PrivateKey)
	s.publicKey = []byte(input.PublicKey)
}

func (s *sshPair) ValueOut() interface{} {
	return sshPairValue{
		PublicKey:  string(s.publicKey),
		PrivateKey: string(s.privateKey),
	}
}

func (s *sshPair) Validate() error {
	if len(s.privateKey)+len(s.publicKey) == 0 {
		return newErrCredUnusable("Must define at least one of `public_key' or `private_key'")
	}

	var privKey *rsa.PrivateKey
	var err error

	if len(s.privateKey) > 0 {
		privatePEMBlock, _ := pem.Decode(s.privateKey)
		if privatePEMBlock == nil {
			return newErrCredUnusable("Private key was not in PEM format")
		}

		privKey, err = x509.ParsePKCS1PrivateKey(privatePEMBlock.Bytes)
		if err != nil {
			return newErrCredUnusable(fmt.Sprintf("Could not parse private key: %s", err))
		}
	}

	var pubKey *ssh.PublicKey
	if len(s.publicKey) > 0 {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(s.publicKey)
		if err != nil {
			return newErrCredUnusable(fmt.Sprintf("Could not parse ssh public key: %s", err))
		}

		if pubKey.Type() != "ssh-rsa" {
			return newErrCredUnusable(fmt.Sprintf("Public key was not ssh-rsa"))
		}
	}

	if len(s.privateKey) > 0 && len(s.publicKey) > 0 {
		//Can't trivially get an rsa.PublicKey to compare modulus, so
		// check pub/priv match through signature verification
		goldblumSays := []byte("i am the pull-out king")
		signer, err := ssh.NewSignerFromKey(privKey)
		if err != nil {
			//already verified the private key, so I don't know why
			//this error would happen
			return err
		}

		signature, err := signer.Sign(rand.Reader, goldblumSays)
		if err != nil {
			//again... uhh... why?
			return err
		}

		err = (*pubKey).Verify(goldblumSays, signature)
		if err != nil {
			return newErrCredUnusable("Private key does not match public key")
		}
	}

	return nil
}
