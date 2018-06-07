package vault

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	errorRenewCert        = "ErrRenewCert"
	messageErrorRenewCert = "Error renewing TLS certificate: "

	successCertRenewed = "CertRenewSuccess"
	messageCertRenewed = "Certificate renewed successfully"
)

func (c *Vault) Renew(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	key, cert, err := c.obtainCertificate(ctx, crt)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, err
}
