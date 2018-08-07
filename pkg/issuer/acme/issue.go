package acme

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorIssueError       = "IssueError"
	errorEncodePrivateKey = "ErrEncodePrivateKey"

	successCertObtained = "CertObtained"

	messageErrorEncodePrivateKey = "Error encoding private key: "
)

func (a *Acme) obtainCertificate(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	if crt.Status.ACMEStatus().OrderRef == nil || crt.Status.ACMEStatus().OrderRef.Name == "" {
		return nil, nil, fmt.Errorf("status.acme.orderRef.name must be set")
	}

	orderName := crt.Status.ACMEStatus().OrderRef.Name
	order, err := a.orderLister.Orders(crt.Namespace).Get(orderName)
	if err != nil {
		// we return err without checking for IsNotFound because Prepare already
		// performs cleanup in the event the referenced Order does not exist.
		// this saves us re-implementing missing order handling here.
		return nil, nil, err
	}

	// TODO: ensure the names on the Order match the desired names for this Certificate
	// If not, we should return an error here in order to trigger the hash-detection
	// logic in Prepare to run.

	cl, err := a.helper.ClientForIssuer(a.issuer)
	if err != nil {
		return nil, nil, err
	}

	commonName := pki.CommonNameForCertificate(crt)
	altNames := pki.DNSNamesForCertificate(crt)

	// get existing certificate private key
	key, err := kube.SecretTLSKey(a.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if apierrors.IsNotFound(err) || errors.IsInvalidData(err) {
		key, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to generate certificate private key: %v", err), false)
			return nil, nil, fmt.Errorf("error generating private key: %s", err.Error())
		}
	}
	if err != nil {
		// don't log these errors to the api as they are likely transient
		return nil, nil, fmt.Errorf("error getting certificate private key: %s", err.Error())
	}

	// generate a csr
	template, err := pki.GenerateCSR(a.issuer, crt)
	if err != nil {
		// TODO: this should probably be classed as a permanant failure
		return nil, nil, err
	}

	derBytes, err := pki.EncodeCSR(template, key)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to generate certificate request: %v", err), false)
		return nil, nil, err
	}

	// obtain a certificate from the acme server
	certSlice, err := cl.FinalizeOrder(ctx, order.Status.FinalizeURL, derBytes)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to finalize order: %v", err), false)
		a.Recorder.Eventf(crt, corev1.EventTypeWarning, errorIssueError, "Failed to finalize order: %v", err)
		return nil, nil, fmt.Errorf("error getting certificate from acme server: %s", err)
	}

	// encode the retrieved certificate
	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certSlice {
		pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}

	a.Recorder.Eventf(crt, corev1.EventTypeNormal, successCertObtained, "Obtained certificate from ACME server")

	glog.Infof("successfully obtained certificate: cn=%q altNames=%+v url=%q", commonName, altNames, order.Status.URL)
	// encode the private key and return
	keyPem, err := pki.EncodePrivateKey(key)
	if err != nil {
		s := messageErrorEncodePrivateKey + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorEncodePrivateKey, s, false)
		return nil, nil, err
	}

	return keyPem, certBuffer.Bytes(), nil
}

func (a *Acme) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	key, cert, err := a.obtainCertificate(ctx, crt)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, err
}
