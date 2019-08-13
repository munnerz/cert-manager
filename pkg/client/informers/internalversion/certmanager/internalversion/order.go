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

// OrderInformer provides access to a shared informer and lister for
// Orders.
type OrderInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() internalversion.OrderLister
}

type orderInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewOrderInformer constructs a new informer for Order type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewOrderInformer(client clientsetinternalversion.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredOrderInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredOrderInformer constructs a new informer for Order type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredOrderInformer(client clientsetinternalversion.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Certmanager().Orders(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Certmanager().Orders(namespace).Watch(options)
			},
		},
		&certmanager.Order{},
		resyncPeriod,
		indexers,
	)
}

func (f *orderInformer) defaultInformer(client clientsetinternalversion.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredOrderInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *orderInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&certmanager.Order{}, f.defaultInformer)
}

func (f *orderInformer) Lister() internalversion.OrderLister {
	return internalversion.NewOrderLister(f.Informer().GetIndexer())
}
