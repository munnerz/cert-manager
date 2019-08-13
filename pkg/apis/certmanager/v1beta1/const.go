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

package v1beta1

import "time"

const (
	// minimum permitted certificate duration by cert-manager
	MinimumCertificateDuration = time.Hour

	// default certificate duration if Issuer.spec.duration is not set
	DefaultCertificateDuration = time.Hour * 24 * 90

	// minimum certificate duration before certificate expiration
	MinimumRenewBefore = time.Minute * 5

	// Default duration before certificate expiration if  Issuer.spec.renewBefore is not set
	DefaultRenewBefore = time.Hour * 24 * 30
)

const (
	ACMEFinalizer = "finalizer.acme.cert-manager.io"
)