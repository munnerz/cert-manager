package acme

import (
	"fmt"

	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// Acme is an issuer for an ACME server. It can be used to register and obtain
// certificates from any ACME server. It supports DNS01 and HTTP01 challenge
// mechanisms.
type Acme struct {
	*controller.Context
	issuer v1alpha1.GenericIssuer
	helper *acme.Helper

	secretsLister corelisters.SecretLister
	orderLister   cmlisters.OrderLister
}

// New returns a new ACME issuer interface for the given issuer.
func New(ctx *controller.Context, issuer v1alpha1.GenericIssuer) (issuer.Interface, error) {
	if issuer.GetSpec().ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	if issuer.GetSpec().ACME.Server == "" ||
		issuer.GetSpec().ACME.PrivateKey.Name == "" ||
		issuer.GetSpec().ACME.Email == "" {
		return nil, fmt.Errorf("acme server, private key and email are required fields")
	}

	// TODO: invent a way to ensure WaitForCacheSync is called for all listers
	// we are interested in

	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()
	orderLister := ctx.SharedInformerFactory.Certmanager().V1alpha1().Orders().Lister()

	a := &Acme{
		Context: ctx,
		helper:  acme.NewHelper(secretsLister, ctx.ClusterResourceNamespace),
		issuer:  issuer,

		secretsLister: secretsLister,
		orderLister:   orderLister,
	}

	return a, nil
}

// Register this Issuer with the issuer factory
func init() {
	controller.RegisterIssuer(controller.IssuerACME, New)
}
