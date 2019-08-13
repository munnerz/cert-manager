package conversion

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
)

type SchemeBackedConverter struct {
	log logr.Logger
	scheme *runtime.Scheme
	codecFactory *serializer.CodecFactory
}

func NewSchemeBackedConverter(log logr.Logger, scheme *runtime.Scheme) *SchemeBackedConverter {
	factory := serializer.NewCodecFactory(scheme)
	return &SchemeBackedConverter{
		log: log,
		scheme:       scheme,
		codecFactory: &factory,
	}
}

func (c *SchemeBackedConverter) Convert(conversionSpec *apiextensionsv1beta1.ConversionRequest) *apiextensionsv1beta1.ConversionResponse {
	status := &apiextensionsv1beta1.ConversionResponse{}

	desiredGV, err := schema.ParseGroupVersion(conversionSpec.DesiredAPIVersion)
	if err != nil {
		status.Result = metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
			Message: fmt.Sprintf("Failed to parse desired apiVersion: %v", err.Error()),
		}
		return status
	}

	serializer := json.NewSerializerWithOptions(json.DefaultMetaFactory, c.scheme, c.scheme, json.SerializerOptions{
		Yaml:   true,
		Pretty: true,
		Strict: false,
	})
	groupVersioner := schema.GroupVersions([]schema.GroupVersion{desiredGV})
	decoder := c.codecFactory.DecoderToVersion(serializer, groupVersioner)
	encoder := c.codecFactory.EncoderForVersion(serializer, groupVersioner)

	c.log.Info("Parsed desired groupVersion", "desired_group_version", desiredGV)
	for _, raw := range conversionSpec.Objects {
		decodedObject, currentGVK, err := decoder.Decode(raw.Raw, nil, nil)
		if err != nil {
			status.Result = metav1.Status{
				Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
				Message: fmt.Sprintf("Failed to convert to desired apiVersion: %v", err.Error()),
			}
			return status
		}
		c.log.Info("Decoded resource", "decoded_group_version_kind", currentGVK)


		buf := bytes.Buffer{}
		if err := encoder.Encode(decodedObject, &buf); err != nil {
			status.Result = metav1.Status{
				Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
				Message: fmt.Sprintf("Failed to convert to desired apiVersion: %v", err.Error()),
			}
			return status
		}

		status.ConvertedObjects = append(status.ConvertedObjects, runtime.RawExtension{Raw: buf.Bytes()})
	}

	status.Result.Status = metav1.StatusSuccess
	return status
}