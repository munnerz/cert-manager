/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhookbootstrap

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// The webhook bootstrapper is responsible for managing the CA used
// by cert-manager's own CRD conversion/validation webhook.
// This is required because whilst the conversion webhook is unavailable, it is
// not guaranteed that certificate issuance can proceed so we have a 'bootstrap
// problem'.
// This controller relies on static configuration passed as arguments in order
// to issue certificates without interacting with cert-manager CRDs:
// - --webhook-ca-secret
// - --webhook-serving-secret
// - --webhook-dns-names
// - --webhook-namespace

type controller struct {
	webhookCASecret      string
	webhookServingSecret string
	webhookDNSNames      []string
	webhookNamespace     string

	secretLister corelisters.SecretLister
	kubeClient   kubernetes.Interface

	// certificateNeedsRenew is a function that can be used to determine whether
	// a certificate currently requires renewal.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	certificateNeedsRenew func(ctx context.Context, cert *x509.Certificate, crt *cmapi.Certificate) bool
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	//log := logf.FromContext(ctx.RootContext, ExperimentalControllerName)

	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ControllerName)

	// obtain references to all the informers used by this controller
	secretsInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		secretsInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.secretLister = secretsInformer.Lister()

	// register handler functions
	secretsInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})

	c.kubeClient = ctx.Client

	c.webhookDNSNames = ctx.WebhookBootstrapOptions.DNSNames
	c.webhookCASecret = ctx.WebhookBootstrapOptions.CASecretName
	c.webhookServingSecret = ctx.WebhookBootstrapOptions.ServingSecretName
	c.webhookNamespace = ctx.WebhookBootstrapOptions.Namespace
	c.certificateNeedsRenew = ctx.IssuerOptions.CertificateNeedsRenew

	return queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	ctx = logf.NewContext(ctx, nil, ControllerName)
	log := logf.FromContext(ctx)

	if len(c.webhookDNSNames) == 0 {
		log.Info("No webhook DNS names provided on start-up, not processing any resources.")
		return nil
	}

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "error parsing resource key in queue")
		return nil
	}

	if c.webhookNamespace != namespace || !(c.webhookCASecret == name || c.webhookServingSecret == name) {
		return nil
	}

	secret, err := c.secretLister.Secrets(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		log.Info("secret resource no longer exists", "key", key)
		return nil
	}
	if err != nil {
		return err
	}

	switch name {
	case c.webhookCASecret:
		return c.syncCASecret(ctx, secret)
	case c.webhookServingSecret:
		return c.syncServingSecret(ctx, secret)
	}

	return nil
}

func (c *controller) syncCASecret(ctx context.Context, secret *corev1.Secret) error {
	log := logf.FromContext(ctx, "ca-secret")
	log = logf.WithResource(log, secret)
	crt := buildCACertificate(secret)

	// read the existing private key
	pkData := readSecretDataKey(secret, corev1.TLSPrivateKeyKey)
	if pkData == nil {
		log.Info("Generating new private key")
		return c.generatePrivateKey(crt, secret)
	}
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		log.Info("Regenerating new private key")
		return c.generatePrivateKey(crt, secret)
	}

	// read the existing certificate
	if !c.certificateRequiresIssuance(ctx, log, secret, pk, crt) {
		return nil
	}

	signedCert, err := selfSignCertificate(crt, pk)
	if err != nil {
		log.Error(err, "Error signing certificate")
		return err
	}

	return c.updateSecret(secret, pkData, signedCert, signedCert)
}

func (c *controller) syncServingSecret(ctx context.Context, secret *corev1.Secret) error {
	log := logf.FromContext(ctx, "ca-secret")
	log = logf.WithResource(log, secret)
	crt := buildServingCertificate(secret, c.webhookDNSNames)

	// first fetch the CA private key & certificate
	caSecret, err := c.secretLister.Secrets(c.webhookNamespace).Get(c.webhookCASecret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Error(err, "ca secret does not yet exist")
			// TODO: automatically sync the serving secret when the ca secret
			//       is updated and return nil here instead
			return err
		}
		return err
	}

	caPKData := readSecretDataKey(caSecret, corev1.TLSPrivateKeyKey)
	caPK, err := pki.DecodePrivateKeyBytes(caPKData)
	if err != nil {
		log.Error(err, "Error decoding CA private key")
		return err
	}

	caCertData := readSecretDataKey(caSecret, corev1.TLSCertKey)
	caCert, err := pki.DecodeX509CertificateBytes(caCertData)
	if err != nil {
		log.Error(err, "Error decoding CA certificate data")
		return err
	}

	// read the existing private key
	pkData := readSecretDataKey(secret, corev1.TLSPrivateKeyKey)
	if pkData == nil {
		log.Info("Generating new private key")
		return c.generatePrivateKey(crt, secret)
	}
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		log.Info("Regenerating new private key")
		return c.generatePrivateKey(crt, secret)
	}
	// read the existing certificate
	if !c.certificateRequiresIssuance(ctx, log, secret, pk, crt) {
		log.Info("Serving certificate already up to date")
		return nil
	}

	// TODO: check to make sure the serving certificate is signed by the CA

	cert, err := pki.GenerateTemplate(crt)
	if err != nil {
		return err
	}
	certData, cert, err := pki.SignCertificate(cert, caCert, pk.Public(), caPK)
	if err != nil {
		return err
	}

	return c.updateSecret(secret, pkData, caCertData, certData)
}

func (c *controller) certificateRequiresIssuance(ctx context.Context, log logr.Logger, secret *corev1.Secret, pk crypto.Signer, crt *cmapi.Certificate) bool {
	// read the existing certificate
	crtData := readSecretDataKey(secret, corev1.TLSCertKey)
	if crtData == nil {
		log.Info("Issuing webhook certificate")
		return true
	}
	cert, err := pki.DecodeX509CertificateBytes(crtData)
	if err != nil {
		log.Info("Re-issuing webhook certificate")
		return true
	}

	// ensure private key is valid for certificate
	matches, err := pki.PublicKeyMatchesCertificate(pk.Public(), cert)
	if err != nil {
		log.Error(err, "internal error checking certificate, re-issuing certificate")
		return true
	}
	if !matches {
		log.Info("certificate does not match private key, re-issuing")
		return true
	}

	// validate the common name is correct
	expectedCN := pki.CommonNameForCertificate(crt)
	if expectedCN != cert.Subject.CommonName {
		log.Info("certificate common name is not as expected, re-issuing")
		return true
	}

	// validate the dns names are correct
	expectedDNSNames := pki.DNSNamesForCertificate(crt)
	if !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) {
		log.Info("certificate dns names are not as expected, re-issuing")
		return true
	}

	// validate the ip addresses are correct
	if !util.EqualUnsorted(pki.IPAddressesToString(cert.IPAddresses), crt.Spec.IPAddresses) {
		log.Info("certificate ip addresses are not as expected, re-issuing")
		return true
	}

	if c.certificateNeedsRenew(ctx, cert, crt) {
		log.Info("certificate requires renewal, re-issuing")
		return true
	}

	return false
}

func readSecretDataKey(secret *corev1.Secret, key string) []byte {
	if secret.Data == nil {
		return nil
	}
	d, ok := secret.Data[key]
	if !ok {
		return nil
	}
	return d
}

func (c *controller) generatePrivateKey(crt *cmapi.Certificate, secret *corev1.Secret) error {
	pk, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return err
	}
	pkData, err := pki.EncodePrivateKey(pk, crt.Spec.KeyEncoding)
	if err != nil {
		return err
	}

	return c.updateSecret(secret, pkData, nil, nil)
}

func selfSignCertificate(crt *cmapi.Certificate, signeeKey crypto.Signer) ([]byte, error) {
	cert, err := pki.GenerateTemplate(crt)
	if err != nil {
		return nil, err
	}
	crtData, _, err := pki.SignCertificate(cert, cert, signeeKey.Public(), signeeKey)
	if err != nil {
		return nil, err
	}
	return crtData, nil
}

func (c *controller) updateSecret(secret *corev1.Secret, pk, ca, crt []byte) error {
	secret = secret.DeepCopy()
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[corev1.TLSPrivateKeyKey] = pk
	secret.Data[corev1.TLSCertKey] = crt
	secret.Data[cmapi.TLSCAKey] = ca
	_, err := c.kubeClient.CoreV1().Secrets(secret.Namespace).Update(secret)
	return err
}

const (
	defaultSelfSignedIssuerName = "cert-manager-webhook-selfsigner"
	defaultCAIssuerName         = "cert-manager-webhook-ca"

	defaultCAKeyAlgorithm = cmapi.RSAKeyAlgorithm
	defaultCAKeySize      = 2048
	defaultCAKeyEncoding  = cmapi.PKCS1

	defaultServingKeyAlgorithm = cmapi.RSAKeyAlgorithm
	defaultServingKeySize      = 2048
	defaultServingKeyEncoding  = cmapi.PKCS1
)

func buildCACertificate(secret *corev1.Secret) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(secret, corev1.SchemeGroupVersion.WithKind("Secret"))},
		},
		Spec: cmapi.CertificateSpec{
			SecretName:   secret.Name,
			Organization: []string{"cert-manager.system"},
			CommonName:   "cert-manager.webhook.ca",
			// root CA is valid for 5 years as we don't currently handle
			// rotating the root properly
			Duration: &metav1.Duration{Duration: time.Hour * 24 * 365 * 5},
			IssuerRef: cmapi.ObjectReference{
				Name: defaultSelfSignedIssuerName,
			},
			IsCA:         true,
			KeyAlgorithm: defaultCAKeyAlgorithm,
			KeySize:      defaultCAKeySize,
			KeyEncoding:  defaultCAKeyEncoding,
		},
	}
}

func buildServingCertificate(secret *corev1.Secret, dnsNames []string) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(secret, corev1.SchemeGroupVersion.WithKind("Secret"))},
		},
		Spec: cmapi.CertificateSpec{
			SecretName:   secret.Name,
			Organization: []string{"cert-manager.system"},
			DNSNames:     dnsNames,
			Duration:     &metav1.Duration{Duration: time.Hour * 24 * 365 * 1},
			IssuerRef: cmapi.ObjectReference{
				Name: defaultCAIssuerName,
			},
			KeyAlgorithm: defaultServingKeyAlgorithm,
			KeySize:      defaultServingKeySize,
			KeyEncoding:  defaultServingKeyEncoding,
		},
	}
}

const (
	ControllerName = "webhook-bootstrap"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		c, err := controllerpkg.New(ctx, ControllerName, &controller{})
		if err != nil {
			return nil, err
		}
		return c.Run, nil
	})
}
