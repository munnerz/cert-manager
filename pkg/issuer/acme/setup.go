/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package acme

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"

	"k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

// Setup will verify an existing ACME registration, or create one if not
// already registered.
func (a *Acme) Setup(ctx context.Context) (issuer.SetupResponse, error) {
	err := a.setup(ctx)
	if err != nil {
		return issuer.SetupResponse{Requeue: true}, err
	}
	return issuer.SetupResponse{}, nil
}

func (a *Acme) setup(ctx context.Context) error {
	// check if user has specified a v1 account URL, and set a status condition if so.
	if newURL, ok := acmev1ToV2Mappings[a.issuer.GetSpec().ACME.Server]; ok {
		a.failedSetup("Config", "Your ACME server URL is set to a v1 endpoint (%s). "+
			"You should update the spec.acme.server field to %q", a.issuer.GetSpec().ACME.Server, newURL)

		// return nil so that Setup only gets called again after the spec is updated.
		// This stops us spamming the event log.
		return nil
	}

	// if the namespace field is not set, we are working on a ClusterIssuer resource
	// therefore we should check for the ACME private key in the 'cluster resource namespace'.
	ns := a.issuer.GetObjectMeta().Namespace
	if ns == "" {
		ns = a.IssuerOptions.ClusterResourceNamespace
	}

	// attempt to obtain the ACME client for this issuer using the 'acme helper'.
	// This will will attempt to retrieve the ACME private key from the apiserver.
	// If retrieving the private key fails, we catch this case and generate a
	// new key.
	cl, err := a.helper.ClientForIssuer(a.issuer)

	if err != nil && !(k8sErrors.IsNotFound(err) || errors.IsInvalidData(err)) {
		return a.failedSetup("Verify", "Failed to verify ACME account: %v", err)
	}

	// Here, we handle the case where a private key does not already exist, or
	// if it does exist, if it is invalid.
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		a.Recorder.Event(a.issuer, v1.EventTypeNormal, "Registering", "Generating new ACME account private key...")
		accountPrivKey, err := a.createAccountPrivateKey(a.issuer.GetSpec().ACME.PrivateKey, ns)
		if err != nil {
			return a.failedSetup("Register", "Failed to generate ACME account private key: %v", err)
		}
		// reset the acme account URI, as it will be set further in the control flow
		a.issuer.GetStatus().ACMEStatus().URI = ""

		cl, err = acme.ClientWithKey(a.issuer, accountPrivKey)
		if err != nil {
			return a.failedSetup("Verify", "Failed to verify ACME account: %v", err)
		}
	}

	account, err := a.accountExists(ctx, cl)
	if err != nil {
		return a.failedSetup("Verify", "Failed to verify ACME account: %v", err)
	}

	if account != nil {
		a.Recorder.Event(a.issuer, v1.EventTypeNormal, "Verified", "Verfified existing registration with ACME server")
		a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, "Verified", "Verfified existing registration with ACME server")
		a.issuer.GetStatus().ACMEStatus().URI = account.URL
		return nil
	}

	account, err = a.registerAccount(ctx, cl)
	if err != nil {
		return a.failedSetup("Register", "Failed to register ACME account: %v", err)
	}

	// registerAccount will also verify the account exists if it already
	// exists.
	account, err = a.registerAccount(ctx, cl)
	if err != nil {
		return a.failedSetup("Register", "Failed to register ACME account: %v", err)
	}

	a.Recorder.Event(a.issuer, v1.EventTypeNormal, "Registered", "Registered new account with ACME server")
	a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, "Registered", "Registered new account with ACME server")
	a.issuer.GetStatus().ACMEStatus().URI = account.URL

	return nil
}

// failedSetup will set the ready condition on the issuer, as well as logging
// an event about the failure.
// 'stage' will be used as part of the 'reason' string, and should be one of
// 'Verify' or 'Register' (to create a reason string like FailedVerify or
// FailedRegister).
// err should be the error that caused the failure, to be used as the message.
// This function will always return the error provided, for convinience when
// using it as part of the Setup function.
func (a *Acme) failedSetup(stage string, errF string, vals ...interface{}) error {
	err := fmt.Errorf(errF, vals...)
	a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, "Failed"+stage, err.Error())
	a.Recorder.Event(a.issuer, v1.EventTypeWarning, "Failed"+stage, err.Error())
	return err
}

// accountExists will return the existing ACME account for the issuer, if it exists.
// If an account does not exist, it will return a nil error as well as a nil
// account.
// All other errors will be returned.
func (a *Acme) accountExists(ctx context.Context, cl client.Interface) (*acmeapi.Account, error) {
	// check if the account already exists
	acc, err := cl.GetAccount(ctx)
	if err == nil {
		return acc, nil
	}

	acmeErr, ok := err.(*acmeapi.Error)
	if !ok || (acmeErr.StatusCode != 400 && acmeErr.StatusCode != 404) {
		return nil, err
	}

	return nil, nil
}

// registerAccount will register a new ACME account with the server. If an
// account with the clients private key already exists, it will attempt to look
// up and verify the corresponding account, and will return that. If this fails
// due to a not found error it will register a new account with the given key.
// The second return value, a boolean, will be true if the account already existed,
// i.e. GetAccount returned an account object.
func (a *Acme) registerAccount(ctx context.Context, cl client.Interface) (*acmeapi.Account, error) {
	acc := &acmeapi.Account{
		Contact:     []string{fmt.Sprintf("mailto:%s", strings.ToLower(a.issuer.GetSpec().ACME.Email))},
		TermsAgreed: true,
	}

	acc, err := cl.CreateAccount(ctx, acc)
	if err != nil {
		return nil, err
	}

	a.Recorder.Event(a.issuer, v1.EventTypeNormal, "Registered", "New account registered with ACME server")

	// TODO: re-enable this check once this field is set by Pebble
	// if acc.Status != acme.StatusValid {
	// 	return nil, fmt.Errorf("acme account is not valid")
	// }

	return acc, nil
}

// createAccountPrivateKey will generate a new RSA private key, and create it
// as a secret resource in the apiserver.
func (a *Acme) createAccountPrivateKey(sel v1alpha1.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	sel = acme.PrivateKeySelector(sel)
	accountPrivKey, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		return nil, err
	}

	_, err = a.Client.CoreV1().Secrets(ns).Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sel.Name,
			Namespace: ns,
		},
		Data: map[string][]byte{
			sel.Key: pki.EncodePKCS1PrivateKey(accountPrivKey),
		},
	})
	if err != nil {
		return nil, err
	}

	a.Recorder.Eventf(a.issuer, v1.EventTypeNormal, "Generated", "Generated a new ACME account private key %q", sel.Name)

	return accountPrivKey, err
}

var acmev1ToV2Mappings = map[string]string{
	"https://acme-v01.api.letsencrypt.org/directory":      "https://acme-v02.api.letsencrypt.org/directory",
	"https://acme-staging.api.letsencrypt.org/directory":  "https://acme-staging-v02.api.letsencrypt.org/directory",
	"https://acme-v01.api.letsencrypt.org/directory/":     "https://acme-v02.api.letsencrypt.org/directory",
	"https://acme-staging.api.letsencrypt.org/directory/": "https://acme-staging-v02.api.letsencrypt.org/directory",
}
