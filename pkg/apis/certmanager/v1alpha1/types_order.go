/*
Copyright 2018 Jetstack.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO: these types should be moved into their own API group once we have a loose
// coupling between ACME Issuers and their solver configurations (see: Solver proposal)

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +kubebuilder:resource:path=orders
type Order struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   OrderSpec   `json:"spec"`
	Status OrderStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OrderList is a list of Orders
type OrderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Order `json:"items"`
}

type OrderSpec struct {
	// IssuerRef references a properly configured ACME-type Issuer which should
	// be used to create this Order.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Order will be marked as failed.
	IssuerRef ObjectReference `json:"issuerRef"`

	// DNSNames is a list of DNS names that should be included as part of the Order
	// validation process.
	DNSNames []string `json:"dnsNames"`

	// Config specifies a mapping from DNS identifiers to how those identifiers
	// should be solved when performing ACME challenges.
	// A config entry must exist for each domain listed in DNSNames.
	Config []DomainSolverConfig `json:"config"`
}

type OrderStatus struct {
	// URL of the Order.
	// This will initially be empty when the resource is first created.
	// The Order controller will populate this field when the Order is first processed.
	// This field will be immutable after it is initially set.
	URL string `json:"url"`

	// FinalizeURL of the Order.
	// This is used to obtain certificates for this order once it has been completed.
	FinalizeURL string `json:"finalizeURL"`

	// State contains the current state of this Order resource.
	// States 'success' and 'expired' are 'final'
	State State `json:"state"`

	// Reason optionally provides more information about a why the order is in
	// the current state.
	Reason string `json:"reason"`

	// Challenges is a list of ChallengeSpecs for Challenges that must be created
	// in order to complete this Order.
	Challenges []ChallengeSpec `json:"challenges,omitempty"`

	// FailureTime stores the time that this order failed.
	// This is used to influence garbage collection and back-off.
	// The order resource will be automatically deleted after 30 minutes has
	// passed since the failure time.
	// +optional
	FailureTime *metav1.Time `json:"failureTime,omitempty"`
}

// State represents the state of an ACME resource, such as an Order.
// The possible options here map to the corresponding values in the
// ACME specification.
// Full details of these values can be found there.
// Clients utilising this type **must** also gracefully handle unknown
// values, as the contents of this enumeration may be added to over time.
type State string

const (
	// Unknown is not a real state as part of the ACME spec.
	// It is used to represent an unrecognised value.
	Unknown State = ""

	// Valid signifies that an ACME resource is in a valid state.
	// If an Order is marked 'valid', all validations on that Order
	// have been completed successfully.
	// This is a transient state as of ACME draft-12
	Valid State = "valid"

	// Ready signifies that an ACME resource is in a ready state.
	// If an Order is marked 'Ready', the corresponding certificate
	// is ready and can be obtained.
	// This is a final state.
	Ready State = "ready"

	// Pending signifies that an ACME resource is still pending and is not yet ready.
	// If an Order is marked 'Pending', the validations for that Order are still in progress.
	// This is a transient state.
	Pending State = "pending"

	// Processing signifies that an ACME resource is being processed by the server.
	// If an Order is marked 'Processing', the validations for that Order are currently being processed.
	// This is a transient state.
	Processing State = "processing"

	// Failed signifies that an ACME resource has failed for some reason.
	// If an Order is marked 'Failed', one of its validations may have failed for some reason.
	// This is a final state.
	Failed State = "failed"

	// Expired signifies that an ACME resource has expired.
	// If an Order is marked 'Expired', one of its validations may have expired or the Order itself.
	// This is a final state.
	Expired State = "expired"
)

type SolverConfig struct {
	HTTP01 *HTTP01SolverConfig `json:"http01,omitempty"`
	DNS01  *DNS01SolverConfig  `json:"dns01,omitempty"`
}

type HTTP01SolverConfig struct {
	Ingress      string  `json:"ingress"`
	IngressClass *string `json:"ingressClass,omitempty"`
}

type DNS01SolverConfig struct {
	Provider string `json:"provider"`
}

type DomainSolverConfig struct {
	Domains      []string `json:"domains"`
	SolverConfig `json:",inline"`
}
