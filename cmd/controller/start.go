package main

import (
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	_ "github.com/jetstack/cert-manager/pkg/controller/certificates"
	_ "github.com/jetstack/cert-manager/pkg/controller/clusterissuers"
	_ "github.com/jetstack/cert-manager/pkg/controller/ingress-shim"
	_ "github.com/jetstack/cert-manager/pkg/controller/issuers"
	_ "github.com/jetstack/cert-manager/pkg/issuer/acme"
	_ "github.com/jetstack/cert-manager/pkg/issuer/ca"
	_ "github.com/jetstack/cert-manager/pkg/issuer/selfsigned"
	_ "github.com/jetstack/cert-manager/pkg/issuer/vault"
)
