package persistence

import (
	"time"

	. "github.com/onsi/ginkgo"
	"github.com/skbkontur/oauth2-proxy/pkg/apis/options"
	sessionsapi "github.com/skbkontur/oauth2-proxy/pkg/apis/sessions"
	"github.com/skbkontur/oauth2-proxy/pkg/sessions/tests"
)

var _ = Describe("Persistence Manager Tests", func() {
	var ms *tests.MockStore
	BeforeEach(func() {
		ms = tests.NewMockStore()
	})
	tests.RunSessionStoreTests(
		func(_ *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
			return NewManager(ms, cookieOpts), nil
		},
		func(d time.Duration) error {
			ms.FastForward(d)
			return nil
		})
})
