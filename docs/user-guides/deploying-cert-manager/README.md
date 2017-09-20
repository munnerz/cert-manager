# Deploying cert-manager

cert-manager usually runs as a Deployment in your cluster. It does not require
any persistent state, as everything is stored in an 'upstream' kubernetes API
server using CustomResourceDefinitions or ThirdPartyResources.

By default, cert-manager will issue certificates in all namespaces. You can
limit the scope of cert-managers operation using the `--namespace` flag.

### 0. Pre-requisites

* Kubernetes cluster with CustomResourceDefinitions or ThirdPartyResource
support

As cert-manager uses custom resources/third party resources to represent
Certificates and Issuers, we must register our custom API types with the
Kubernetes API server. How we do this varies slightly from Kubernetes 1.7
onwards:

#### Kubernetes 1.7 and later

Kubernetes 1.7 introduced [CustomResourceDefinitions](https://kubernetes.io/docs/concepts/api-extension/custom-resources/).
A pre-made CRD for cert-manager is in `docs/crd.yaml`. We can install it with:

```
$ kubectl create -f https://raw.githubusercontent.com/jetstack-experimental/cert-manager/master/docs/crd.yaml
```

#### Kubernetes 1.6 and below

As Kubernetes 1.6 does not support CustomResourceDefinitions, we must instead
use ThirdPartyResources, the older, now deprecated version of
CustomResourceDefinition. A pre-made TPR for cert-manager is in
`docs/tpr.yaml`. We can install it with:

```
$ kubectl create -f https://raw.githubusercontent.com/jetstack-experimental/cert-manager/master/docs/tpr.yaml
```

### 1. Deploy cert-manager

To deploy the latest version of cert-manager, run:

```
$ kubectl create -f https://raw.githubusercontent.com/jetstack-experimental/cert-manager/master/docs/cert-manager.yaml
```

**NOTE**

* In future this may be replaced with a Helm chart.
* There are currently no official RBAC roles defined for cert-manager (see [#34](https://github.com/jetstack-experimental/cert-manager/issues/34))
