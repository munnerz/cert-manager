package vault

import (
	"fmt"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

const (
	errorVaultNamespaceRequired     = "ErrVaultNSRequired"
	errorVaultConfigRequired        = "ErrVaultConfigRequired"
	errorVaultServerAndPathRequired = "ErrVaultServerAndPathRequired"
	errorVaultAuthFieldsRequired    = "ErrVaultAuthFieldsRequired"
	errorVaultDurationInvalid       = "ErrVaultDurationInvalid"

	messageNamespaceRequired     = "resource namespace cannot be empty"
	messageVaultConfigRequired   = "Vault config cannot be empty"
	messageServerAndPathRequired = "Vault server and path are required fields"
	messsageAuthFieldsRequired   = "Vault tokenSecretRef or appRoleSecretRef field is required"
	messageAuthFieldRequired     = "Vault tokenSecretRef and appRoleSecretRef fields can be set on the same issuer"
	messageVaultDurationInvalid  = "Vault %s"
)

type Vault struct {
	issuer v1alpha1.GenericIssuer

	client   kubernetes.Interface
	cmclient clientset.Interface
	recorder record.EventRecorder

	secretsLister corelisters.SecretLister

	// issuerResourcesNamespace is a namespace to store resources in. This is
	// here so we can easily support ClusterIssuers with the same codepath. By
	// setting this field to either the namespace of the Issuer, or the
	// clusterResourceNamespace specified on the CLI, we can easily continue
	// to work with supplemental (e.g. secrets) resources without significant
	// refactoring.
	issuerResourcesNamespace string
}

func NewVault(issuerObj v1alpha1.GenericIssuer,
	cl kubernetes.Interface,
	cmclient clientset.Interface,
	recorder record.EventRecorder,
	resourceNamespace string,
	secretsLister corelisters.SecretLister) (issuer.Interface, error) {

	if resourceNamespace == "" {
		return nil, updateEventAndCondition(fmt.Errorf(messageNamespaceRequired), errorVaultNamespaceRequired, issuerObj, recorder)
	}

	if issuerObj.GetSpec().Vault == nil {
		return nil, updateEventAndCondition(fmt.Errorf(messageVaultConfigRequired), errorVaultConfigRequired, issuerObj, recorder)
	}

	if issuerObj.GetSpec().Vault.Server == "" ||
		issuerObj.GetSpec().Vault.Path == "" {
		return nil, updateEventAndCondition(fmt.Errorf(messageServerAndPathRequired), errorVaultServerAndPathRequired, issuerObj, recorder)
	}

	if issuerObj.GetSpec().Vault.Auth.TokenSecretRef.Name == "" &&
		issuerObj.GetSpec().Vault.Auth.AppRoleSecretRef.Name == "" {
		return nil, updateEventAndCondition(fmt.Errorf(messsageAuthFieldsRequired), errorVaultAuthFieldsRequired, issuerObj, recorder)
	}

	if issuerObj.GetSpec().Vault.Auth.TokenSecretRef.Name != "" &&
		issuerObj.GetSpec().Vault.Auth.AppRoleSecretRef.Name != "" {
		return nil, updateEventAndCondition(fmt.Errorf(messageAuthFieldRequired), errorVaultAuthFieldsRequired, issuerObj, recorder)
	}

	if err := issuer.ValidateDuration(issuerObj); err != nil {
		return nil, updateEventAndCondition(fmt.Errorf(messageVaultDurationInvalid, err.Error()), errorVaultDurationInvalid, issuerObj, recorder)
	}

	return &Vault{
		issuer:                   issuerObj,
		client:                   cl,
		cmclient:                 cmclient,
		recorder:                 recorder,
		issuerResourcesNamespace: resourceNamespace,
		secretsLister:            secretsLister,
	}, nil
}

func updateEventAndCondition(err error, event string, issuerObj v1alpha1.GenericIssuer, recorder record.EventRecorder) error {
	glog.V(4).Infof("%s: %s", issuerObj.GetObjectMeta().Name, err.Error())
	recorder.Event(issuerObj, v1.EventTypeWarning, event, err.Error())
	issuerObj.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, event, err.Error())
	return err
}

// Register this Issuer with the issuer factory
func init() {
	issuer.Register(issuer.IssuerVault, func(issuer v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		issuerResourcesNamespace := issuer.GetObjectMeta().Namespace
		if issuerResourcesNamespace == "" {
			issuerResourcesNamespace = ctx.ClusterResourceNamespace
		}
		return NewVault(
			issuer,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			issuerResourcesNamespace,
			ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		)
	})
}
