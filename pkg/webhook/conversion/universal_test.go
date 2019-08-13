package conversion

import (
	"reflect"
	"testing"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/klogr"
	"k8s.io/utils/diff"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/install"
)

func TestConvertCertificate(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	log := klogr.New()
	c := NewSchemeBackedConverter(log, scheme)
	tests := map[string]testT{
		"convert Certificate from v1alpha1 to v1beta1": {
			inputRequest: apiextensionsv1beta1.ConversionRequest{
				DesiredAPIVersion: "certmanager.k8s.io/v1beta1",
				Objects:           []runtime.RawExtension{
					{
						Raw: []byte(`apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: testing
  namespace: abc
spec:
  secretName: secret-name
  dnsNames:
  - example.com
`),
					},
				},
			},
			expectedResponse: apiextensionsv1beta1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				ConvertedObjects:           []runtime.RawExtension{
					{
						Raw: []byte(`apiVersion: certmanager.k8s.io/v1beta1
kind: Certificate
metadata:
  creationTimestamp: null
  name: testing
  namespace: abc
spec:
  dnsNames:
  - example.com
  issuerRef:
    name: ""
  secretName: secret-name
status: {}
`),
					},
				},
			},
		},
		"convert Certificate from v1beta1 to v1alpha1": {
			inputRequest: apiextensionsv1beta1.ConversionRequest{
				DesiredAPIVersion: "certmanager.k8s.io/v1alpha1",
				Objects:           []runtime.RawExtension{
					{
						Raw: []byte(`apiVersion: certmanager.k8s.io/v1beta1
kind: Certificate
metadata:
  name: testing
  namespace: abc
spec:
  secretName: secret-name
  dnsNames:
  - example.com
`),
					},
				},
			},
			expectedResponse: apiextensionsv1beta1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				ConvertedObjects:           []runtime.RawExtension{
					{
						Raw: []byte(`apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  creationTimestamp: null
  name: testing
  namespace: abc
spec:
  dnsNames:
  - example.com
  issuerRef:
    name: ""
  secretName: secret-name
status: {}
`),
					},
				},
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			runTest(t, c.Convert, test)
		})
	}
}

type testT struct {
	inputRequest apiextensionsv1beta1.ConversionRequest
	expectedResponse apiextensionsv1beta1.ConversionResponse
}

type convertFn func(*apiextensionsv1beta1.ConversionRequest) *apiextensionsv1beta1.ConversionResponse

func runTest(t *testing.T, fn convertFn, test testT) {
	resp := fn(&test.inputRequest)
	if !reflect.DeepEqual(&test.expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&test.expectedResponse, resp))
	}
}
