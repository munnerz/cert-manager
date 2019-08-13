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

// Code generated by informer-gen. DO NOT EDIT.

package internalversion

import (
	time "time"

	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager"
	clientsetinternalversion "github.com/jetstack/cert-manager/pkg/client/clientset/internalversion"
	internalinterfaces "github.com/jetstack/cert-manager/pkg/client/informers/internalversion/internalinterfaces"
	internalversion "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// CertificateRequestInformer provides access to a shared informer and lister for
// CertificateRequests.
type CertificateRequestInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() internalversion.CertificateRequestLister
}

type certificateRequestInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewCertificateRequestInformer constructs a new informer for CertificateRequest type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewCertificateRequestInformer(client clientsetinternalversion.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredCertificateRequestInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredCertificateRequestInformer constructs a new informer for CertificateRequest type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredCertificateRequestInformer(client clientsetinternalversion.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Certmanager().CertificateRequests(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Certmanager().CertificateRequests(namespace).Watch(options)
			},
		},
		&certmanager.CertificateRequest{},
		resyncPeriod,
		indexers,
	)
}

func (f *certificateRequestInformer) defaultInformer(client clientsetinternalversion.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredCertificateRequestInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *certificateRequestInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&certmanager.CertificateRequest{}, f.defaultInformer)
}

func (f *certificateRequestInformer) Lister() internalversion.CertificateRequestLister {
	return internalversion.NewCertificateRequestLister(f.Informer().GetIndexer())
}