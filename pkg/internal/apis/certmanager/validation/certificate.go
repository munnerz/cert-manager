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

package validation

import (
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/api/util"
	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

// Validation functions for cert-manager Certificate types

func ValidateCertificateSpec(crt *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if crt.SecretName == "" {
		el = append(el, field.Required(fldPath.Child("secretName"), "must be specified"))
	}

	el = append(el, validateIssuerRef(crt.IssuerRef, fldPath)...)

	if len(crt.CommonName) == 0 && len(crt.DNSNames) == 0 && len(crt.URISANs) == 0 {
		el = append(el, field.Required(fldPath.Child("commonName", "dnsNames", "uriSANs"),
			"at least one of commonName, dnsNames, or uriSANs must be set"))
	}

	// if a common name has been specified, ensure it is no longer than 64 chars
	if len(crt.CommonName) > 64 {
		el = append(el, field.TooLong(fldPath.Child("commonName"), crt.CommonName, 64))
	}

	if len(crt.IPAddresses) > 0 {
		el = append(el, validateIPAddresses(crt, fldPath)...)
	}
	if crt.PrivateKey.Size < 0 {
		el = append(el, field.Invalid(fldPath.Child("privateKey", "size"), crt.PrivateKey.Size, "cannot be less than zero"))
	}
	switch crt.PrivateKey.Algorithm {
	case cmapi.RSAKeyAlgorithm:
		if crt.PrivateKey.Size > 0 && (crt.PrivateKey.Size < 2048 || crt.PrivateKey.Size > 8192) {
			el = append(el, field.Invalid(fldPath.Child("privateKey", "size"), crt.PrivateKey.Size, "must be between 2048 & 8192 for rsa keyAlgorithm"))
		}
	case cmapi.ECDSAKeyAlgorithm:
		if crt.PrivateKey.Size > 0 && crt.PrivateKey.Size != 256 && crt.PrivateKey.Size != 384 && crt.PrivateKey.Size != 521 {
			el = append(el, field.NotSupported(fldPath.Child("privateKey", "size"), crt.PrivateKey.Size, []string{"256", "384", "521"}))
		}
	default:
		el = append(el, field.Invalid(fldPath.Child("privateKey", "algorithm"), crt.PrivateKey.Algorithm, "must be either empty or one of rsa or ecdsa"))
	}

	if crt.Duration != nil || crt.RenewBefore != nil {
		el = append(el, ValidateDuration(crt, fldPath)...)
	}
	if len(crt.Usages) > 0 {
		el = append(el, validateUsages(crt, fldPath)...)
	}
	switch crt.Format.Type {
	case "", cmapi.PKCS1, cmapi.PKCS8:
	default:
		el = append(el, field.Invalid(fldPath.Child("format", "type"), crt.Format.Type, "must be either empty or one of pkcs1 or pkcs8"))
	}
	return el
}

func ValidateCertificate(obj runtime.Object) field.ErrorList {
	crt := obj.(*cmapi.Certificate)
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs
}

func validateIssuerRef(issuerRef cmmeta.ObjectReference, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	issuerRefPath := fldPath.Child("issuerRef")
	if issuerRef.Name == "" {
		el = append(el, field.Required(issuerRefPath.Child("name"), "must be specified"))
	}
	if issuerRef.Group == "" || issuerRef.Group == cmapi.SchemeGroupVersion.Group {
		switch issuerRef.Kind {
		case "":
		case "Issuer", "ClusterIssuer":
		default:
			el = append(el, field.Invalid(issuerRefPath.Child("kind"), issuerRef.Kind, "must be one of Issuer or ClusterIssuer"))
		}
	}
	return el
}

func validateIPAddresses(a *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	if len(a.IPAddresses) <= 0 {
		return nil
	}
	el := field.ErrorList{}
	for i, d := range a.IPAddresses {
		ip := net.ParseIP(d)
		if ip == nil {
			el = append(el, field.Invalid(fldPath.Child("ipAddresses").Index(i), d, "invalid IP address"))
		}
	}
	return el
}

func validateUsages(a *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	for i, u := range a.Usages {
		_, kok := util.KeyUsageType(cmapiv1alpha2.KeyUsage(u))
		_, ekok := util.ExtKeyUsageType(cmapiv1alpha2.KeyUsage(u))
		if !kok && !ekok {
			el = append(el, field.Invalid(fldPath.Child("usages").Index(i), u, "unknown keyusage"))
		}
	}
	return el
}

func ValidateDuration(crt *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	duration := util.DefaultCertDuration(crt.Duration)
	renewBefore := cmapiv1alpha2.DefaultRenewBefore
	if crt.RenewBefore != nil {
		renewBefore = crt.RenewBefore.Duration
	}
	if duration < cmapiv1alpha2.MinimumCertificateDuration {
		el = append(el, field.Invalid(fldPath.Child("duration"), duration, fmt.Sprintf("certificate duration must be greater than %s", cmapiv1alpha2.MinimumCertificateDuration)))
	}
	if renewBefore < cmapiv1alpha2.MinimumRenewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate renewBefore must be greater than %s", cmapiv1alpha2.MinimumRenewBefore)))
	}
	if duration <= renewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", duration, renewBefore)))
	}
	return el
}
