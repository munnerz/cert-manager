# Issuers

Issuers in cert-manager provide a mechanism to obtain and renew TLS
certificates. They are designed to be easily extendable and flexible.

An issuer is defined by a simple interface:

```golang
type Interface interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup() error
	// Prepare the certificate for issuance. In this case of ACME, this verify
    // the existing authorizations for domains listed on the ceritificate, or
    // attempt to obtain new authorizations otherwise.
	Prepare(*v1alpha1.Certificate) error
	// Issue attempts to issue a certificate as described by the certificate
	// resource given
	Issue(*v1alpha1.Certificate) ([]byte, []byte, error)
	// Renew attempts to renew the certificate describe by the certificate
	// resource given. If no certificate exists, an error is returned.
	Renew(*v1alpha1.Certificate) ([]byte, []byte, error)
}
```
