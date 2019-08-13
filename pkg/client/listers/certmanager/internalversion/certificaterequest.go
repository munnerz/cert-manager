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

// Code generated by lister-gen. DO NOT EDIT.

package internalversion

import (
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// CertificateRequestLister helps list CertificateRequests.
type CertificateRequestLister interface {
	// List lists all CertificateRequests in the indexer.
	List(selector labels.Selector) (ret []*certmanager.CertificateRequest, err error)
	// CertificateRequests returns an object that can list and get CertificateRequests.
	CertificateRequests(namespace string) CertificateRequestNamespaceLister
	CertificateRequestListerExpansion
}

// certificateRequestLister implements the CertificateRequestLister interface.
type certificateRequestLister struct {
	indexer cache.Indexer
}

// NewCertificateRequestLister returns a new CertificateRequestLister.
func NewCertificateRequestLister(indexer cache.Indexer) CertificateRequestLister {
	return &certificateRequestLister{indexer: indexer}
}

// List lists all CertificateRequests in the indexer.
func (s *certificateRequestLister) List(selector labels.Selector) (ret []*certmanager.CertificateRequest, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanager.CertificateRequest))
	})
	return ret, err
}

// CertificateRequests returns an object that can list and get CertificateRequests.
func (s *certificateRequestLister) CertificateRequests(namespace string) CertificateRequestNamespaceLister {
	return certificateRequestNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// CertificateRequestNamespaceLister helps list and get CertificateRequests.
type CertificateRequestNamespaceLister interface {
	// List lists all CertificateRequests in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*certmanager.CertificateRequest, err error)
	// Get retrieves the CertificateRequest from the indexer for a given namespace and name.
	Get(name string) (*certmanager.CertificateRequest, error)
	CertificateRequestNamespaceListerExpansion
}

// certificateRequestNamespaceLister implements the CertificateRequestNamespaceLister
// interface.
type certificateRequestNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all CertificateRequests in the indexer for a given namespace.
func (s certificateRequestNamespaceLister) List(selector labels.Selector) (ret []*certmanager.CertificateRequest, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanager.CertificateRequest))
	})
	return ret, err
}

// Get retrieves the CertificateRequest from the indexer for a given namespace and name.
func (s certificateRequestNamespaceLister) Get(name string) (*certmanager.CertificateRequest, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(certmanager.Resource("certificaterequest"), name)
	}
	return obj.(*certmanager.CertificateRequest), nil
}
