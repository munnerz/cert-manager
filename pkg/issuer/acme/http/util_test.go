package http

import (
	"testing"

	"github.com/jetstack/cert-manager/test/util/generate"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
)

const (
	defaultTestIssuerName              = "test-issuer"
	defaultTestIssuerKind              = v1alpha1.IssuerKind
	defaultTestNamespace               = "default"
	defaultTestCertificateName         = "test-cert"
	defaultTestCertificateIngressClass = "nginx"
)

type solverFixture struct {
	// The Solver under test
	Solver *Solver
	*test.Builder

	// Issuer to be passed to functions on the Solver (a default will be used if nil)
	Issuer v1alpha1.GenericIssuer
	// Challenge resource to use during tests
	Challenge *v1alpha1.Challenge

	// PreFn will run before the test is run, but after the fixture has been initialised.
	// This is useful if you want to load the clientset with some resources *after* the
	// fixture has been created.
	PreFn func(*testing.T, *solverFixture)
	// CheckFn should performs checks to ensure the output of the test is as expected.
	// Optional additional values may be provided, which represent the output of the
	// function under test.
	CheckFn func(*testing.T, *solverFixture, ...interface{})
	// Err should be true if an error is expected from the function under test
	Err bool

	// testResources is used to store references to resources used or created during
	// the test.
	testResources map[string]interface{}
}

func (s *solverFixture) Setup(t *testing.T) {
	if s.Issuer == nil {
		s.Issuer = generate.Issuer(generate.IssuerConfig{
			Name:      defaultTestIssuerName,
			Namespace: defaultTestNamespace,
		})
	}
	if s.testResources == nil {
		s.testResources = map[string]interface{}{}
	}
	if s.Builder == nil {
		s.Builder = &test.Builder{}
	}
	s.Solver = buildFakeSolver(s.Builder)
	if s.PreFn != nil {
		s.PreFn(t, s)
		s.Builder.Sync()
	}
}

func (s *solverFixture) Finish(t *testing.T, args ...interface{}) {
	defer s.Builder.Stop()
	// resync listers before running checks
	s.Builder.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(t, s, args...)
	}
}

func buildFakeSolver(b *test.Builder) *Solver {
	b.Start()
	s := NewSolver(b.Context)
	b.Sync()
	return s
}

func strPtr(s string) *string {
	return &s
}
