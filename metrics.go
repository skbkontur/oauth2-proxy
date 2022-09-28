package main

import (
	"strings"
)

func (p *OAuthProxy) incrementBasicSuccess(entryAlias string, method string) {
	if p.StatsD != nil {
		entryAlias = strings.Replace(entryAlias, ".", "-", -1)
		entryMetricName := "basicAuth.authenticated." + entryAlias + "." + method
		totalMetricName := "basicAuth.authenticated.total"
		p.StatsD.Increment(entryMetricName)
		p.StatsD.Increment(totalMetricName)
	}
}

func (p *OAuthProxy) incrementBasicFailed(method string) {
	if p.StatsD != nil {
		entryMetricName := "basicAuth.unauthenticated.attemptedWith." + method
		totalMetricName := "basicAuth.unauthenticated.total"
		p.StatsD.Increment(entryMetricName)
		p.StatsD.Increment(totalMetricName)
	}
}

func (p *OAuthProxy) incrementAuthorizeFailed(method string) {
	if p.StatsD != nil {
		entryMetricName := "basicAuth.unauthorized.attemptedWith." + method
		totalMetricName := "basicAuth.unauthorized.total"
		p.StatsD.Increment(entryMetricName)
		p.StatsD.Increment(totalMetricName)
	}
}

func (p *OAuthProxy) incrementCallbackFailed(method string) {
	if p.StatsD != nil {
		entryMetricName := "basicAuth.callbackfail.attemptedWith." + method
		totalMetricName := "basicAuth.callbackfail.total"
		p.StatsD.Increment(entryMetricName)
		p.StatsD.Increment(totalMetricName)
	}
}
