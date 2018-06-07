package ca

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func (c *SelfSigned) Renew(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if err != nil {
		return nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, signeeKey)

	if err != nil {
		return nil, nil, err
	}

	return pki.EncodePKCS1PrivateKey(signeeKey), certPem, nil
}
