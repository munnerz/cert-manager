package validation

import (
	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Validation functions for cert-manager v1alpha1 Certificate types

func ValidateCertificate(crt *v1alpha1.Certificate) field.ErrorList {
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateCertificateSpec(crt *v1alpha1.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if crt.SecretName == "" {
		el = append(el, field.Required(fldPath.Child("secretName"), "must be specified"))
	}
	issuerRefPath := fldPath.Child("issuerRef")
	if crt.IssuerRef.Name == "" {
		el = append(el, field.Required(issuerRefPath.Child("name"), "must be specified"))
	}
	if crt.IssuerRef.Kind == "" {
		// For now we disable this check in order to support older versions where
		// defaulting doesn't occur
		glog.Infof("Certificate does not set issuerRef.kind - " +
			"in future versions of cert-manager, this will be a hard failure.")
		// el = append(el, field.Required(issuerRefPath.Child("kind"), "must be specified"))
	}
	if len(crt.CommonName) == 0 && len(crt.DNSNames) == 0 {
		el = append(el, field.Required(fldPath.Child("dnsNames"), "at least one dnsName is required if commonName is not set"))
	}
	if crt.ACME != nil {
		el = append(el, ValidateACMECertificateConfig(crt.ACME, fldPath.Child("acme"))...)
	}
	return el
}

func ValidateACMECertificateConfig(a *v1alpha1.ACMECertificateConfig, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	for _, cfg := range a.Config {
		el = append(el, ValidateACMECertificateDomainConfig(&cfg, fldPath)...)
	}
	return el
}

func ValidateACMECertificateDomainConfig(a *v1alpha1.ACMECertificateDomainConfig, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if a.DNS01 != nil && a.HTTP01 != nil {
		el = append(el, field.Invalid(fldPath, "http-01 and dns-01 set", "cannot specify multiple solvers for a single domain"))
	}
	if a.DNS01 != nil {
		el = append(el, ValidateACMECertificateDNS01Config(a.DNS01, fldPath.Child("dns01"))...)
	}
	if a.HTTP01 != nil {
		el = append(el, ValidateACMECertificateHTTP01Config(a.HTTP01, fldPath.Child("http01"))...)
	}
	return el
}

func ValidateACMECertificateDNS01Config(a *v1alpha1.ACMECertificateDNS01Config, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if a.Provider == "" {
		el = append(el, field.Required(fldPath.Child("provider"), "provider name must be set"))
	}
	return el
}

func ValidateACMECertificateHTTP01Config(a *v1alpha1.ACMECertificateHTTP01Config, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	// TODO: ensure 'ingress' is a valid resource name (i.e. DNS name)
	return el
}
