package selfsigned

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func TestSetup(t *testing.T) {
	c := &SelfSigned{
		issuer: newSelfSignedIssuer(),
	}
	err := c.Setup(context.Background())
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
	if !c.issuer.HasCondition(v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	}) {
		t.Errorf("Expected Issuer to have Ready condition")
	}
}

func newSelfSignedIssuer() v1alpha1.GenericIssuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				SelfSigned: &v1alpha1.SelfSignedIssuer{},
			},
		},
	}
}
