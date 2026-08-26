package node

import (
	"testing"

	"github.com/go-gost/x/config"
	coreRouting "github.com/go-gost/core/routing"
	"github.com/go-gost/x/routing"
)

func TestFilterToMatcherRule_Precedence(t *testing.T) {
	for _, fc := range []struct{ name, host string }{
		{"dot", ".example.com"},
		{"star", "*.example.com"},
	} {
		t.Run(fc.name, func(t *testing.T) {
			rule := filterToMatcherRule(&config.NodeFilterConfig{
				Host: fc.host, Protocol: "http", Path: "/api",
			})
			m, err := routing.NewMatcher(rule)
			if err != nil {
				t.Fatalf("parse %q: %v", rule, err)
			}
			if m.Match(&coreRouting.Request{Host: "example.com", Protocol: "https", Path: "/other"}) {
				t.Errorf("rule %q matched apex+https+/other (should reject)", rule)
			}
			if !m.Match(&coreRouting.Request{Host: "example.com", Protocol: "http", Path: "/api/v1"}) {
				t.Errorf("rule %q rejected apex+http+/api/v1 (should accept)", rule)
			}
			if !m.Match(&coreRouting.Request{Host: "www.example.com", Protocol: "http", Path: "/api"}) {
				t.Errorf("rule %q rejected www+http+/api (should accept)", rule)
			}
		})
	}
}
