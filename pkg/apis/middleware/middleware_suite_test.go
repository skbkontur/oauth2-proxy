package middleware_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/skbkontur/oauth2-proxy/pkg/logger"
)

// TestMiddlewareSuite and related tests are in a *_test package
// to prevent circular imports with the `logger` package which uses
// this functionality
func TestMiddlewareSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Middleware API")
}
