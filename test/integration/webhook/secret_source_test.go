package webhook

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	logtesting "github.com/jetstack/cert-manager/pkg/logs/testing"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/pkg/webhook/server/tls"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

// Start an instance of the Secret-backed TLS certificate watcher and ensure it
// correctly detects a Secret being created.
func TestWebhookSecretCertificateSource(t *testing.T) {
	config, stop := framework.RunControlPlane(t)
	defer stop()
	cl := kubernetes.NewForConfigOrDie(config)

	source := tls.SecretCertificateSource{
		SecretNamespace: "testns",
		SecretName:      "testsecret",
		RESTConfig:      config,
		Log:             logtesting.TestLogger{T: t},
	}
	stopCh := make(chan struct{})
	// run the 'secret source' controller in the background
	go func() {
		if err := source.Run(stopCh); err != nil {
			t.Fatalf("Unexpected error running source: %v", err)
		}
	}()

	_, err := source.GetCertificate(nil)
	if err != tls.ErrNotAvailable {
		t.Fatalf("Expected certificate source to return ErrNotAvailable but got: %v", err)
	}

	pkPEM, certPEM := generatePrivateKeyAndCertificate(t)
	_, err = cl.CoreV1().Secrets(source.SecretNamespace).Create(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: source.SecretNamespace,
			Name:      source.SecretName,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: pkPEM,
			corev1.TLSCertKey:       certPEM,
		},
		Type: corev1.SecretTypeTLS,
	})
	if err != nil {
		t.Fatalf("Failed to create Secret test fixture: %v", err)
	}

	// allow the controller 5s to discover the Secret - this is far longer than
	// it should ever take.
	if err := wait.Poll(time.Millisecond*500, time.Second*5, func() (done bool, err error) {
		bundle, err := source.GetCertificate(nil)
		if err == tls.ErrNotAvailable {
			t.Logf("TLS certificate still not available, waiting...")
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if len(bundle.Certificate) == 0 {
			return false, fmt.Errorf("bundle contained no certificate data")
		}
		if bundle.PrivateKey == nil {
			return false, fmt.Errorf("bundle contained no private key data")
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Failed waiting for source to detect new Secret data: %v", err)
	}
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func generatePrivateKeyAndCertificate(t *testing.T) ([]byte, []byte) {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pkBytes, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.RSA,
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 10),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := pki.EncodeX509(cert)
	if err != nil {
		t.Fatal(err)
	}

	return pkBytes, certBytes
}
