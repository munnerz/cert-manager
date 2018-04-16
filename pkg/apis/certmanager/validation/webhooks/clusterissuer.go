package webhooks

import (
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	restclient "k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type ClusterIssuerAdmissionHook struct {
}

func (c *ClusterIssuerAdmissionHook) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error {
	return nil
}

func (c *ClusterIssuerAdmissionHook) ValidatingResource() (plural schema.GroupVersionResource, singular string) {
	gv := v1alpha1.SchemeGroupVersion
	gv.Group = "admission." + gv.Group
	// override version to be the version of the admissionresponse resource
	gv.Version = "v1beta1"
	return gv.WithResource("clusterissuers"), "clusterissuer"
}

func (c *ClusterIssuerAdmissionHook) Validate(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	status := &admissionv1beta1.AdmissionResponse{}
	status.Allowed = true
	return status
}
