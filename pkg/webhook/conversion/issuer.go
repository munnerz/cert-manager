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

package conversion

import (
	"github.com/go-logr/logr"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	restclient "k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// issuerConversionHook implements a conversion webhook that expects all
// objects passed to it to be cert-manager Issuer resources.
// It uses the provided runtime.Scheme to convert resources to the desired
// api version.
type issuerConversionHook struct {
	universal *SchemeBackedConverter
}

func NewIssuerConversionHook(log logr.Logger, scheme *runtime.Scheme) *clusterIssuerConversionHook {
	return &clusterIssuerConversionHook{
		universal: NewSchemeBackedConverter(log, scheme),
	}
}

func (c *issuerConversionHook) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error {
	return nil
}

func (c *issuerConversionHook) ConvertingResource() (plural schema.GroupVersionResource, singular string) {
	gv := apiextensionsv1beta1.SchemeGroupVersion
	gv.Group = "conversion." + v1alpha1.SchemeGroupVersion.Group
	return gv.WithResource("clusterissuers"), "clusterissuer"
}

func (c *issuerConversionHook) Convert(conversionSpec *apiextensionsv1beta1.ConversionRequest) *apiextensionsv1beta1.ConversionResponse {
	return c.universal.Convert(conversionSpec)
}
