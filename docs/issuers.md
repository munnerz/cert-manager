# Issuers

cert-manager has the concept of 'Issuers' that define a source of TLS
certificates, including any configuration required for that source.

An example of an Issuer is ACME. A simple ACME issuer could be defined as:

```yaml
kind: Issuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    # The ACME server URL
    server: https://acme-v01.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: user@example.com
    # Name of a secret used to store the ACME account private key
    privateKey: letsncrypt-prod
```

This is the simplest of ACME issuers - it specifies no DNS-01 challenge
providers, nor does it specify any HTTP-01 challenge options. It is