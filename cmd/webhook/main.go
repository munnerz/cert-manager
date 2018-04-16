package main

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/webhooks"
	"github.com/openshift/generic-admission-server/pkg/cmd"
)

var certHook cmd.ValidatingAdmissionHook = &webhooks.CertificateAdmissionHook{}
var issuerHook cmd.ValidatingAdmissionHook = &webhooks.IssuerAdmissionHook{}
var clusterIssuerHook cmd.ValidatingAdmissionHook = &webhooks.ClusterIssuerAdmissionHook{}

func main() {
	cmd.RunAdmissionServer(
		certHook,
		issuerHook,
		clusterIssuerHook,
	)
}
