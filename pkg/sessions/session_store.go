package sessions

import (
	"fmt"

	"github.com/skbkontur/oauth2-proxy/pkg/apis/options"
	"github.com/skbkontur/oauth2-proxy/pkg/apis/sessions"
	"github.com/skbkontur/oauth2-proxy/pkg/sessions/cookie"
	"github.com/skbkontur/oauth2-proxy/pkg/sessions/redis"
)

// NewSessionStore creates a SessionStore from the provided configuration
func NewSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	switch opts.Type {
	case options.CookieSessionStoreType:
		return cookie.NewCookieSessionStore(opts, cookieOpts)
	case options.RedisSessionStoreType:
		return redis.NewRedisSessionStore(opts, cookieOpts)
	default:
		return nil, fmt.Errorf("unknown session store type '%s'", opts.Type)
	}
}
