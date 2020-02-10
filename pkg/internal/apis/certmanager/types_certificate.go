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

package certmanager

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Certificate is a type to represent a Certificate from ACME
type Certificate struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CertificateSpec
	Status CertificateStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertificateList is a list of Certificates
type CertificateList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Certificate
}

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	// Full X509 name specification (https://golang.org/pkg/crypto/x509/pkix/#Name).
	Subject *X509Subject

	// PrivateKey configures options for the private key used with this
	// certificate.
	PrivateKey PrivateKeyConfig

	// Format configures the output format of the named `secretName` Secret
	// resource.
	Format CertificateFormat

	// A valid Certificate requires at least one of a CommonName, DNSName, or
	// URISAN to be valid.

	// CommonName is a common name to be used on the Certificate.
	// The CommonName should have a length of 64 characters or fewer to avoid
	// generating invalid CSRs.
	CommonName string

	// Certificate default Duration
	Duration *metav1.Duration

	// Certificate renew before expiration duration
	RenewBefore *metav1.Duration

	// DNSNames is a list of subject alt names to be used on the Certificate.
	DNSNames []string

	// IPAddresses is a list of IP addresses to be used on the Certificate
	IPAddresses []string

	// URISANs is a list of URI Subject Alternative Names to be set on this
	// Certificate.
	URISANs []string

	// SecretName is the name of the secret resource to store this secret in
	SecretName string

	// IssuerRef is a reference to the issuer for this certificate.
	// If the 'kind' field is not set, or set to 'Issuer', an Issuer resource
	// with the given name in the same namespace as the Certificate will be used.
	// If the 'kind' field is set to 'ClusterIssuer', a ClusterIssuer with the
	// provided name will be used.
	// The 'name' field in this stanza is required at all times.
	IssuerRef cmmeta.ObjectReference

	// IsCA will mark this Certificate as valid for signing.
	// This implies that the 'cert sign' usage is set
	IsCA bool

	// Usages is the set of x509 actions that are enabled for a given key. Defaults are ('digital signature', 'key encipherment') if empty
	Usages []KeyUsage
}

type CertificateFormat struct {
	// CertificateFormatType is the private key cryptography standards (PKCS)
	// for this certificate's private key to be encoded in. If provided, allowed
	// values are "pkcs1" and "pkcs8" standing for PKCS#1 and PKCS#8, respectively.
	// If Type is not specified, then PKCS#1 will be used by default.
	Type CertificateFormatType
}

type CertificateFormatType string

const (
	PKCS1 CertificateFormatType = "pkcs1"
	PKCS8 CertificateFormatType = "pkcs8"
)

// PrivateKeyConfig contains configuration for a private key associated with
// a Certificate object.
type PrivateKeyConfig struct {
	// KeySize is the key bit size of the corresponding private key for this certificate.
	// If provided, value must be between 2048 and 8192 inclusive when KeyAlgorithm is
	// empty or is set to "rsa", and value must be one of (256, 384, 521) when
	// KeyAlgorithm is set to "ecdsa".
	Size int

	// KeyAlgorithm is the private key algorithm of the corresponding private key
	// for this certificate. If provided, allowed values are either "rsa" or "ecdsa"
	// If KeyAlgorithm is specified and KeySize is not provided,
	// key size of 256 will be used for "ecdsa" key algorithm and
	// key size of 2048 will be used for "rsa" key algorithm.
	Algorithm KeyAlgorithm
}

type KeyAlgorithm string

const (
	RSAKeyAlgorithm   KeyAlgorithm = "rsa"
	ECDSAKeyAlgorithm KeyAlgorithm = "ecdsa"
)

// X509Subject Full X509 name specification
type X509Subject struct {
	// Organizations to be used on the Certificate.
	Organizations []string
	// Countries to be used on the Certificate.
	Countries []string
	// Organizational Units to be used on the Certificate.
	OrganizationalUnits []string
	// Cities to be used on the Certificate.
	Localities []string
	// State/Provinces to be used on the Certificate.
	Provinces []string
	// Street addresses to be used on the Certificate.
	StreetAddresses []string
	// Postal codes to be used on the Certificate.
	PostalCodes []string
	// Serial number to be used on the Certificate.
	SerialNumber string
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	Conditions []CertificateCondition

	LastFailureTime *metav1.Time

	// The expiration time of the certificate stored in the secret named
	// by this resource in spec.secretName.
	NotAfter *metav1.Time
}

// CertificateCondition contains condition information for an Certificate.
type CertificateCondition struct {
	// Type of the condition, currently ('Ready').
	Type CertificateConditionType

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status cmmeta.ConditionStatus

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime *metav1.Time

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string
}

// CertificateConditionType represents an Certificate condition value.
type CertificateConditionType string

const (
	// CertificateConditionReady indicates that a certificate is ready for use.
	// This is defined as:
	// - The target secret exists
	// - The target secret contains a certificate that has not expired
	// - The target secret contains a private key valid for the certificate
	// - The commonName and dnsNames attributes match those specified on the Certificate
	CertificateConditionReady CertificateConditionType = "Ready"
)
