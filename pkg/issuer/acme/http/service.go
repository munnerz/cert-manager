package http

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (s *Solver) ensureService(ch *v1alpha1.Challenge) (*corev1.Service, error) {
	existingServices, err := s.getServicesForChallenge(ch)
	if err != nil {
		return nil, err
	}
	if len(existingServices) == 1 {
		return existingServices[0], nil
	}
	if len(existingServices) > 1 {
		errMsg := fmt.Sprintf("multiple challenge solver services found for certificate '%s/%s'. Cleaning up existing services.", ch.Namespace, ch.Name)
		glog.Infof(errMsg)
		err := s.cleanupServices(ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(errMsg)
	}

	glog.Infof("No existing HTTP01 challenge solver service found for Certificate %q. One will be created.", ch.Namespace+"/"+ch.Name)
	return s.createService(ch)
}

// getServicesForChallenge returns a list of services that were created to solve
// http challenges for the given domain
func (s *Solver) getServicesForChallenge(ch *v1alpha1.Challenge) ([]*corev1.Service, error) {
	podLabels := podLabels(ch)
	selector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*req)
	}

	serviceList, err := s.serviceLister.Services(ch.Namespace).List(selector)
	if err != nil {
		return nil, err
	}

	var relevantServices []*corev1.Service
	for _, service := range serviceList {
		if !metav1.IsControlledBy(service, ch) {
			glog.Infof("Found service %q with acme-order-url annotation set to that of Certificate %q"+
				"but it is not owned by the Certificate resource, so skipping it.", service.Namespace+"/"+service.Name, ch.Namespace+"/"+ch.Name)
			continue
		}
		relevantServices = append(relevantServices, service)
	}

	return relevantServices, nil
}

// createService will create the service required to solve this challenge
// in the target API server.
func (s *Solver) createService(ch *v1alpha1.Challenge) (*corev1.Service, error) {
	return s.Client.CoreV1().Services(ch.Namespace).Create(buildService(ch))
}

func buildService(ch *v1alpha1.Challenge) *corev1.Service {
	podLabels := podLabels(ch)
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-acme-http-solver-",
			Namespace:    ch.Namespace,
			Labels:       podLabels,
			Annotations: map[string]string{
				"auth.istio.io/8089": "NONE",
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       acmeSolverListenPort,
					TargetPort: intstr.FromInt(acmeSolverListenPort),
				},
			},
			Selector: podLabels,
		},
	}
}

func (s *Solver) cleanupServices(ch *v1alpha1.Challenge) error {
	services, err := s.getServicesForChallenge(ch)
	if err != nil {
		return err
	}
	var errs []error
	for _, service := range services {
		// TODO: should we call DeleteCollection here? We'd need to somehow
		// also ensure ownership as part of that request using a FieldSelector.
		err := s.Client.CoreV1().Services(service.Namespace).Delete(service.Name, nil)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}
