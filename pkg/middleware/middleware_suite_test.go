package middleware

import (
	"net/http"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	middlewareapi "github.com/skbkontur/oauth2-proxy/pkg/apis/middleware"
	"github.com/skbkontur/oauth2-proxy/pkg/logger"
)

func TestMiddlewareSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Middleware")
}

func testHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte("test"))
	})
}

func testUpstreamHandler(upstream string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		scope.Upstream = upstream

		rw.WriteHeader(200)
		rw.Write([]byte("test"))
	})
}
