Creating a simple Vault based issuer
====================================

cert-manager can be used to obtain certificates from `Hashicorp's
Vault <https://www.vaultproject.io/>`__.

Vault Installation
==================

To install Vault your best course of action is to follow the official
`documentation <https://www.vaultproject.io/intro/getting-started/deploy.html>`__.

Vault PKI Backend
=================

The PKI Secrets Engine needs to be initialized for cert-manager to be
able to generate certificate. The official Vault documentation can be
found
`here <https://www.vaultproject.io/docs/secrets/pki/index.html>`__.

Supported Vault Authentication
==============================

The issuer can authenticate to Vault with a secret containing:
- a Vault token
- a Vault appRole/secretId

Vault AppRole
-------------

A `Vault AppRole <https://www.vaultproject.io/docs/auth/approle.html>`__
is the easiest way to authenticate securely to Vault with cert-manager. The role
ID and the secret ID are stored in a secret.

For example:

.. code:: yaml

    apiVersion: v1
    kind: Secret
    type: Opaque
    metadata:
      name: cert-manager-vault-approle
      namespace: kube-system
    data:
      roleId: "MjI..."
      secretId: "MDI..."

Where roleId and secretId are the base 64 encoded values of the appRole
giving access to the pki backend in Vault.

We can now create a cluster issuer referencing this secret:

.. code:: yaml

    apiVersion: certmanager.k8s.io/v1alpha1
    kind: ClusterIssuer
    metadata:
      name: vault-cluster-issuer
    spec:
      vault:
        auth:
          appRoleSecretRef:
            name: cert-manager-vault-approle
        path: pki_int/sign/example-dot-com
        server: https://vault

Where *path* is the Vault role path of the PKI backend and *server* is
the Vault server base URL.

Vault Token
-----------

This authentication method uses a token when calling Vault. A root token is
generated during Vault installation which do not expire. *A root token should only
be used for testing purpose only*.

It is possible to use a token given by another authentication method in Vault in
cert-manager. This token can be refreshed by another process having the
crendentials necessary to negotiate and refresh the token TTL indefinitely.
You need to be aware that cert-manager do not refresh this token.

To know more about Vault token you can consult the `Vault documentation <https://www.vaultproject.io/docs/concepts/tokens.html>`__.

The secret containing the token must have a key named token. Here an
example:

.. code:: yaml

    apiVersion: v1
    kind: Secret
    type: Opaque
    metadata:
      name: cert-manager-vault-token
      namespace: kube-system
    data:
      token: "MjI..."

Where the token value is the base 64 encoded value of the token giving
access to the PKI backend in Vault.

We can now create an issuer referencing this secret:

.. code:: yaml

    apiVersion: certmanager.k8s.io/v1alpha1
    kind: ClusterIssuer
    metadata:
      name: vault-cluster-issuer
    spec:
      vault:
        auth:
          tokenSecretRef:
            name: cert-manager-vault-token
        path: pki_int/sign/example-dot-com
        server: https://vault

Where *path* is the Vault role path of the PKI backend and *server* is
the Vault server base URL.
