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

package tls

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

// SecretCertificateSource provides certificate data for a golang HTTP server by
// watching a Secret resource in a Kubernetes API server.
type SecretCertificateSource struct {
	// Namespace of the Secret resource containing the certificate and private
	// key data. This will be watched for changes.
	SecretNamespace string

	// Name of the Secret resource containing the certificate and private key
	// data. This will be watched for changes.
	SecretName string

	// RESTConfig used to connect to the apiserver.
	RESTConfig *rest.Config

	// Log is an optional logger to write informational and error messages to.
	// If not specified, no messages will be logged.
	Log logr.Logger

	cachedCertificate *tls.Certificate
	cachedCertBytes   []byte
	cachedKeyBytes    []byte
	lock              sync.Mutex
}

var _ CertificateSource = &SecretCertificateSource{}

func (f *SecretCertificateSource) Run(stopCh <-chan struct{}) error {
	if f.Log == nil {
		f.Log = crlog.NullLogger{}
	}

	cl, err := kubernetes.NewForConfig(f.RESTConfig)
	if err != nil {
		return err
	}

	escapedName := fields.EscapeValue(f.SecretName)
	factory := informers.NewSharedInformerFactoryWithOptions(cl, time.Minute,
		informers.WithNamespace(f.SecretNamespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = "metadata.name=" + escapedName
		}),
	)
	informer := factory.Core().V1().Secrets().Informer()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    f.handleAdd,
		UpdateFunc: f.handleUpdate,
		// don't do anything on Delete events, just continue serving with the
		// previous certificate until a new one is available.
	})

	// start the informers and wait for the cache to sync
	factory.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, informer.HasSynced) {
		return fmt.Errorf("failed waiting for informer caches to sync")
	}

	// wait for stopCh to be closed
	<-stopCh
	return nil
}

var ErrNotAvailable = fmt.Errorf("no TLS certificate available")

func (f *SecretCertificateSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	if f.cachedCertificate == nil {
		return nil, ErrNotAvailable
	}
	return f.cachedCertificate, nil
}

func (f *SecretCertificateSource) Healthy() bool {
	return f.cachedCertificate != nil
}

func (f *SecretCertificateSource) handleAdd(obj interface{}) {
	f.updateCachedSecret(obj.(*corev1.Secret))
}

func (f *SecretCertificateSource) handleUpdate(_, obj interface{}) {
	f.updateCachedSecret(obj.(*corev1.Secret))
}

// updateCachedSecret will read private key and certificate data from the
// Secret resource and update the cached tls.Certificate if the data has
// changed.
func (f *SecretCertificateSource) updateCachedSecret(s *corev1.Secret) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if s.Data == nil {
		f.Log.Info("Secret contained no data, ignoring...")
		return
	}

	keyData, ok := s.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		f.Log.Info("Secret containing no private key data, ignoring...")
		return
	}

	certData, ok := s.Data[corev1.TLSCertKey]
	if !ok {
		f.Log.Info("Secret containing no certificate data, ignoring...")
		return
	}

	if bytes.Compare(keyData, f.cachedKeyBytes) == 0 && bytes.Compare(certData, f.cachedCertBytes) == 0 {
		f.Log.V(logf.DebugLevel).Info("Key and certificate in the Secret have not changed")
		return
	}

	f.Log.Info("Detected private key or certificate data has changed. Reloading certificate")

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		f.Log.Error(err, "Failed to parse TLS private key or certificate")
		return
	}

	f.cachedCertBytes = certData
	f.cachedKeyBytes = keyData
	f.cachedCertificate = &cert

	f.Log.Info("Reloaded TLS certificate")

	return
}
