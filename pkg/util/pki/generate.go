package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// GenerateRSAPrivateKey generates a RSA private key with the parameters as specified
// on the Certificate resource.
func GenerateRSAPrivateKey(crt *v1alpha1.Certificate) (*rsa.PrivateKey, error) {
	keySize := int(crt.Spec.KeySize)
	if keySize == 0 {
		keySize = 2048
	}
	return rsa.GenerateKey(rand.Reader, keySize)
}

func EncodePKCS1PrivateKey(pk *rsa.PrivateKey) []byte {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}

	return pem.EncodeToMemory(block)
}
