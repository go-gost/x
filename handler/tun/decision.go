package tun

import "github.com/AeroCore-IO/avionics/pkg/decision"

// DecisionEvaluator abstracts rule evaluation; implementations can be injected by callers.
type DecisionEvaluator interface {
	CheckTrafficRules(input decision.RuleInput) *decision.TrafficDecision
	// ResolveMetadata allows the evaluator to enrich the input with application context (AppID, Hostname)
	// based on the 5-tuple.
	ResolveMetadata(srcIP, dstIP string, srcPort, dstPort int, proto string) (appID string, hostname string)
}

// DecisionRuleInput re-exports the shared rule input type for convenience.
type DecisionRuleInput = decision.RuleInput

// TrafficDecision re-exports the shared traffic decision type for convenience.
type TrafficDecision = decision.TrafficDecision
