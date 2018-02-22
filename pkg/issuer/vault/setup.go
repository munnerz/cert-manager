package vault

import (
	"context"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/api/core/v1"
)

const (
	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"

	messageVaultClientInitFailed         = "Failed to initialize Vault client: "
	errorVaultClientInitFailed           = "ErrVaultClientInit"
	messageVaultHealthCheckFailed        = "Failed to call Vault health check: "
	errorVaultHealthCheckFailed          = "ErrVaultHealthCheck"
	messageVaultStatusVerificationFailed = "Vault is not initialized or is sealed: "
	errorVaultStatusVerificationFailed   = "ErrVaultStatus"
)

func (v *Vault) Setup(ctx context.Context) error {
	client, err := v.initVaultClient()
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.recorder.Event(v.issuer, v1.EventTypeWarning, errorVaultClientInitFailed, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVaultClientInitFailed, s)
		return err
	}

	health, err := client.Sys().Health()
	if err != nil {
		s := messageVaultHealthCheckFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.recorder.Event(v.issuer, v1.EventTypeWarning, errorVaultHealthCheckFailed, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVaultHealthCheckFailed, s)
		return err
	}

	if !health.Initialized || health.Sealed {
		s := messageVaultStatusVerificationFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.recorder.Event(v.issuer, v1.EventTypeWarning, errorVaultStatusVerificationFailed, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVaultStatusVerificationFailed, s)
		return err
	}

	glog.Info(messageVaultVerified)
	v.recorder.Event(v.issuer, v1.EventTypeNormal, successVaultVerified, messageVaultVerified)
	v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}
