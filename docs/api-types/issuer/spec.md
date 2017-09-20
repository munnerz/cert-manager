# Issuer spec

The full spec for an Issuer can be seen in [/pkg/apis/certmanager/v1alpha1/types.go].
It contains the most up to date copy of the Issuer specification, and should
be used as the canonical source for the API schema.

All Issuers must define their type. Right now, only ACME issuers are supported.
Each issuer type has it's own configuration structure within the Issuer spec.
You should set the approrpriate config structure within your issuer so that
cert-manager can determine which issuing backend to use. For example, the
configuration structure for an ACME issuer is named `acme`, so we'd enable it
like so:

```yaml
apiVersion: certmanager.k8s.io
kind: Issuer
metadata:
  name: example-issuer
spec:
  acme:
    # configuration for this ACME issuer goes here
```

## ACME configuration

In order to use the ACME provider, there are a small number of required fields.
Optional additional DNS providers can be configured on an issuer, however they
are not required in order to issue certificates.

### ACME issuer HTTP01 configuration

The ACME issuer does not require any additional configuration in order to
support HTTP01 challenge validation. All valid ACME issuers are able to issue
certificates validated with HTTP01.

### ACME issuer with no configured DNS providers

Below is an ACME issuer that has been configured to only allow issuing
certificates validated with HTTP01 challenges. A new ACME account will be
registered if required, using a private key stored in a Secret in the same
namespace as the Issuer named `example-issuer-account-key`. It will use the
provided email address on the registration, and register the account with the
listed ACME server (the letsencrypt staging server in this case).

```yaml
apiVersion: certmanager.k8s.io
kind: Issuer
metadata:
  name: example-issuer
spec:
  acme:
    email: user@example.com
	server: https://acme-staging.api.letsencrypt.org/directory
	privateKey: example-issuer-account-key
```

### ACME issuer DNS provider configuration

The ACME issuer can also contain DNS provider configuration, which can be used
by Certificates using this Issuer in order to validate DNS01 challenge
requests:

```yaml
apiVersion: certmanager.k8s.io
kind: Issuer
metadata:
  name: example-issuer
spec:
  acme:
    email: user@example.com
	server: https://acme-staging.api.letsencrypt.org/directory
	privateKey: example-issuer-account-key
	dns-01:
	  providers:
	  - name: prod-clouddns
	    clouddns:
		  serviceAccount:
		    name: prod-clouddns-svc-acct-secret
			key: service-account.json
```

Each issuer can specify multiple different DNS01 challenge providers, and
it is also possible to have multiple instances of the same DNS provider on a
single Issuer (e.g. two clouddns accounts could be set, each with their own
name).

#### Supported DNS01 challenge providers

A number of different DNS providers are supported for the ACME issuer. Below is
a listing of them all, with an example block of configuration:

##### Google CloudDNS

```yaml
clouddns:
  serviceAccount:
    name: prod-clouddns-svc-acct-secret
    key: service-account.json
```

##### Amazon Route53

```yaml
route53:
  accessKeyID: AKIAIOSFODNN7EXAMPLE
  region: eu-west-1
  secretAccessKey:
    name: prod-route53-credentials-secret
    key: secret-access-key
```

##### Cloudflare

```yaml
cloudflare:
  email: my-cloudflare-acc@example.com
  secretAccessKey:
    name: cloudflare-api-key-secret
    key: api-key
```
