package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/adler32"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	reasonCreateOrder    = "CreateOrder"
	reasonDomainVerified = "DomainVerified"
	reasonSelfCheck      = "SelfCheck"

	errorInvalidConfig = "InvalidConfig"
	errorCleanupError  = "CleanupError"
	errorValidateError = "ValidateError"
	errorBackoff       = "Backoff"

	messagePresentChallenge = "Presenting %s challenge for domain %s"
	messageSelfCheck        = "Performing self-check for domain %s"

	// the amount of time to wait before attempting to create a new order after
	// an order has failed.s
	prepareAttemptWaitPeriod = time.Minute * 5
)

func buildOrder(crt *v1alpha1.Certificate) *v1alpha1.Order {
	dnsNames := sets.NewString(crt.Spec.DNSNames...)
	if crt.Spec.CommonName != "" {
		dnsNames.Insert(crt.Spec.CommonName)
	}
	o := &v1alpha1.Order{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: crt.Name + "-",
		},
		Spec: v1alpha1.OrderSpec{
			IssuerRef: crt.Spec.IssuerRef,
			DNSNames:  dnsNames.List(),
			Config:    crt.Spec.ACME.Config,
		},
	}
	return o
}

// Prepare will ensure the issuer has been initialised and is ready to issue
// certificates for the domains listed on the Certificate resource.
//
// It will send the appropriate Letsencrypt authorizations, and complete
// challenge requests if neccessary.
func (a *Acme) Prepare(ctx context.Context, crt *v1alpha1.Certificate) error {
	acmeStatus := crt.Status.ACMEStatus()

	existingOrderName := ""
	if acmeStatus.OrderRef != nil {
		existingOrderName = acmeStatus.OrderRef.Name
	}

	var existingOrder *v1alpha1.Order
	var err error
	if existingOrderName != "" {
		existingOrder, err = a.orderLister.Orders(crt.Namespace).Get(existingOrderName)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
			// if the order is not found, we will proceed to create a new one
		}
	}

	newOrder := buildOrder(crt)
	if existingOrder == nil {
		// TODO: add back-off logic here
		existingOrder, err = a.CMClient.CertmanagerV1alpha1().Orders(crt.Namespace).Create(newOrder)
		if err != nil {
			return err
		}

		acmeStatus.OrderRef = &v1alpha1.LocalObjectReference{
			Name: existingOrder.Name,
		}
	}

	oldHash, err := hashOrder(existingOrder)
	if err != nil {
		return err
	}
	newHash, err := hashOrder(newOrder)
	if err != nil {
		return err
	}

	// The Certificate has changed in some way.
	// We should delete the existing order, and create a new one.
	if oldHash != newHash {
		err := a.CMClient.CertmanagerV1alpha1().Orders(existingOrder.Namespace).Delete(existingOrder.Name, nil)
		if err != nil {
			// ignore not found errors
			if !apierrors.IsNotFound(err) {
				return err
			}
		}

		existingOrder, err = a.CMClient.CertmanagerV1alpha1().Orders(crt.Namespace).Create(newOrder)
		if err != nil {
			return err
		}

		acmeStatus.OrderRef = &v1alpha1.LocalObjectReference{
			Name: existingOrder.Name,
		}
	}

	if acme.IsFailureState(existingOrder.Status.State) {
		// TODO: set last failure time on the certificate and mark it as failed.
		// we also need to be careful to not enter an update loop on this field.
		nowTime := metav1.NewTime(time.Now())
		crt.Status.LastFailureTime = &nowTime
	}

	if existingOrder.Status.State != v1alpha1.Ready {
		return fmt.Errorf("order %q for Certificate %q is in %q state instead of 'ready'. Waiting until Order is completed before issuing certificate", existingOrder.Name, crt.Name, existingOrder.Status.State)
	}

	return nil
}

func hashOrder(o *v1alpha1.Order) (uint32, error) {
	if o == nil {
		return 0, nil
	}

	orderSpecBytes, err := json.Marshal(o.Spec)
	if err != nil {
		return 0, err
	}

	return adler32.Checksum(orderSpecBytes), nil
}
