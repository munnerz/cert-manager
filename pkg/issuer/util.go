package issuer

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func ValidateDuration(issuer v1alpha1.GenericIssuer) error {
	if issuer.GetSpec().Duration != 0 && issuer.GetSpec().RenewBefore == 0 &&
		issuer.GetSpec().Duration <= MinimumCertificateDuration {
		return fmt.Errorf("certificate duration must be greater than 30 days if spec.renewBefore is not set (%s)", MinimumCertificateDuration)
	}

	if issuer.GetSpec().Duration != 0 && issuer.GetSpec().RenewBefore != 0 &&
		issuer.GetSpec().Duration < issuer.GetSpec().RenewBefore {
		return fmt.Errorf("certificate duration (%s) must be greater than renewBefore (%s)", issuer.GetSpec().Duration, issuer.GetSpec().RenewBefore)
	}

	if issuer.GetSpec().RenewBefore != 0 && issuer.GetSpec().RenewBefore < MinimumCertificateRenewalWindowDuration {
		return fmt.Errorf("certificate renewBefore (%s) value must be greater than %s", issuer.GetSpec().RenewBefore, MinimumCertificateRenewalWindowDuration)
	}

	return nil
}
