package routing

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/go-gost/core/routing"
	"github.com/go-gost/x/routing/rules"
	"golang.org/x/exp/slices"
)

var (
	defaultParser rules.Parser
)

func init() {
	var matchers []string
	for matcher := range httpFuncs {
		matchers = append(matchers, matcher)
	}

	parser, err := rules.NewParser(matchers)
	if err != nil {
		panic(err)
	}

	defaultParser = parser
}

type matcher struct {
	// matchers tree structure reflecting the rule.
	tree matchersTree
}

func NewMatcher(rule string) (routing.Matcher, error) {
	parse, err := defaultParser.Parse(rule)
	if err != nil {
		return nil, fmt.Errorf("error while parsing rule %s: %w", rule, err)
	}

	buildTree, ok := parse.(rules.TreeBuilder)
	if !ok {
		return nil, fmt.Errorf("error while parsing rule %s", rule)
	}

	var matchers matchersTree
	err = matchers.addRule(buildTree(), httpFuncs)
	if err != nil {
		return nil, fmt.Errorf("error while adding rule %s: %w", rule, err)
	}

	return &matcher{
		tree: matchers,
	}, nil
}

func (m *matcher) Match(req *routing.Request) bool {
	if m == nil {
		return false
	}

	return m.tree.match(req)
}

// matchersTree represents the matchers tree structure.
type matchersTree struct {
	// matcher is a matcher func used to match HTTP request properties.
	// If matcher is not nil, it means that this matcherTree is a leaf of the tree.
	// It is therefore mutually exclusive with left and right.
	matcher func(*routing.Request) bool
	// operator to combine the evaluation of left and right leaves.
	operator string
	// Mutually exclusive with matcher.
	left  *matchersTree
	right *matchersTree
}

func (m *matchersTree) match(req *routing.Request) bool {
	if m == nil {
		// This should never happen as it should have been detected during parsing.
		return false
	}

	if m.matcher != nil {
		return m.matcher(req)
	}

	switch m.operator {
	case "or":
		return m.left.match(req) || m.right.match(req)
	case "and":
		return m.left.match(req) && m.right.match(req)
	default:
		// This should never happen as it should have been detected during parsing.
		return false
	}
}

type matcherFuncs map[string]func(*matchersTree, ...string) error

func (m *matchersTree) addRule(rule *rules.Tree, funcs matcherFuncs) error {
	switch rule.Matcher {
	case "and", "or":
		m.operator = rule.Matcher
		m.left = &matchersTree{}
		err := m.left.addRule(rule.RuleLeft, funcs)
		if err != nil {
			return fmt.Errorf("error while adding rule %s: %w", rule.Matcher, err)
		}

		m.right = &matchersTree{}
		return m.right.addRule(rule.RuleRight, funcs)
	default:
		err := rules.CheckRule(rule)
		if err != nil {
			return fmt.Errorf("error while checking rule %s: %w", rule.Matcher, err)
		}

		err = funcs[rule.Matcher](m, rule.Value...)
		if err != nil {
			return fmt.Errorf("error while adding rule %s: %w", rule.Matcher, err)
		}

		if rule.Not {
			matcherFunc := m.matcher
			m.matcher = func(req *routing.Request) bool {
				return !matcherFunc(req)
			}
		}
	}

	return nil
}

var httpFuncs = map[string]func(*matchersTree, ...string) error{
	"ClientIP":     expectNParameters(clientIP, 1),
	"Proto":        expectNParameters(proto, 1),
	"Host":         expectNParameters(host, 1),
	"HostRegexp":   expectNParameters(hostRegexp, 1),
	"Method":       expectNParameters(method, 1),
	"Path":         expectNParameters(path, 1),
	"PathRegexp":   expectNParameters(pathRegexp, 1),
	"PathPrefix":   expectNParameters(pathPrefix, 1),
	"Header":       expectNParameters(header, 1, 2),
	"HeaderRegexp": expectNParameters(headerRegexp, 1, 2),
	"Query":        expectNParameters(query, 1, 2),
	"QueryRegexp":  expectNParameters(queryRegexp, 1, 2),
}

func expectNParameters(fn func(*matchersTree, ...string) error, n ...int) func(*matchersTree, ...string) error {
	return func(tree *matchersTree, s ...string) error {
		if !slices.Contains(n, len(s)) {
			return fmt.Errorf("unexpected number of parameters; got %d, expected one of %v", len(s), n)
		}

		return fn(tree, s...)
	}
}

func clientIP(tree *matchersTree, clientIP ...string) error {
	ip := net.ParseIP(clientIP[0])

	var ipNet *net.IPNet
	if ip == nil {
		_, ipNet, _ = net.ParseCIDR(clientIP[0])
	}
	if ip == nil && ipNet == nil {
		return fmt.Errorf("invalid value %q for ClientIP matcher", clientIP[0])
	}

	tree.matcher = func(req *routing.Request) bool {
		if req.ClientIP == nil {
			return false
		}

		if ip != nil {
			return ip.Equal(req.ClientIP)
		}

		return ipNet.Contains(req.ClientIP)
	}

	return nil
}

func proto(tree *matchersTree, protos ...string) error {
	proto := strings.ToLower(protos[0])

	tree.matcher = func(req *routing.Request) bool {
		// logger.Default().Debugf("proto: %s %s", proto, req.Protocol)
		return proto == req.Protocol
	}

	return nil
}

func method(tree *matchersTree, methods ...string) error {
	method := strings.ToUpper(methods[0])

	tree.matcher = func(req *routing.Request) bool {
		return method == req.Method
	}

	return nil
}

func host(tree *matchersTree, hosts ...string) error {
	host := hosts[0]

	if !IsASCII(host) {
		return fmt.Errorf("invalid value %q for Host matcher, non-ASCII characters are not allowed", host)
	}

	host = strings.ToLower(strings.TrimSpace(host))

	if strings.HasPrefix(host, "*") {
		host = host[1:]
		if !strings.HasPrefix(host, ".") {
			host = "." + host
		}
	}

	tree.matcher = func(req *routing.Request) bool {
		// logger.Default().Debugf("host: %s %s", host, req.Host)
		reqHost := strings.ToLower(strings.TrimSpace(parseHost(req.Host)))
		if len(reqHost) == 0 {
			return false
		}

		if reqHost == host {
			return true
		}

		if host[0] == '.' && strings.HasSuffix(reqHost, host[1:]) {
			return true
		}

		return false
	}

	return nil
}

func hostRegexp(tree *matchersTree, hosts ...string) error {
	host := hosts[0]

	if !IsASCII(host) {
		return fmt.Errorf("invalid value %q for HostRegexp matcher, non-ASCII characters are not allowed", host)
	}

	re, err := regexp.Compile(host)
	if err != nil {
		return fmt.Errorf("compiling HostRegexp matcher: %w", err)
	}

	tree.matcher = func(req *routing.Request) bool {
		// logger.Default().Debugf("hostRegexp: %s %s", host, req.Host)
		return re.MatchString(strings.ToLower(strings.TrimSpace(parseHost(req.Host))))
	}

	return nil
}

func path(tree *matchersTree, paths ...string) error {
	path := paths[0]

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path %q does not start with a '/'", path)
	}

	tree.matcher = func(req *routing.Request) bool {
		return req.Path == path
	}

	return nil
}

func pathRegexp(tree *matchersTree, paths ...string) error {
	path := paths[0]

	re, err := regexp.Compile(path)
	if err != nil {
		return fmt.Errorf("compiling PathPrefix matcher: %w", err)
	}

	tree.matcher = func(req *routing.Request) bool {
		return re.MatchString(req.Path)
	}

	return nil
}

func pathPrefix(tree *matchersTree, paths ...string) error {
	path := paths[0]

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path %q does not start with a '/'", path)
	}

	tree.matcher = func(req *routing.Request) bool {
		return strings.HasPrefix(req.Path, path)
	}

	return nil
}

func header(tree *matchersTree, headers ...string) error {
	key := http.CanonicalHeaderKey(headers[0])

	var value string
	var hasValue bool
	if len(headers) == 2 {
		value = headers[1]
		hasValue = true
	}

	tree.matcher = func(req *routing.Request) bool {
		if req.Header == nil {
			return false
		}

		values, ok := req.Header[key]
		if !ok {
			return false
		}

		if !hasValue {
			return true
		}

		for _, headerValue := range values {
			if headerValue == value {
				return true
			}
		}

		return false
	}

	return nil
}

func headerRegexp(tree *matchersTree, headers ...string) error {
	if len(headers) == 1 {
		return header(tree, headers...)
	}

	key, value := http.CanonicalHeaderKey(headers[0]), headers[1]

	re, err := regexp.Compile(value)
	if err != nil {
		return fmt.Errorf("compiling HeaderRegexp matcher: %w", err)
	}

	tree.matcher = func(req *routing.Request) bool {
		if req.Header == nil {
			return false
		}

		for _, headerValue := range req.Header[key] {
			if re.MatchString(headerValue) {
				return true
			}
		}

		return false
	}

	return nil
}

func query(tree *matchersTree, queries ...string) error {
	key := queries[0]

	var value string
	var hasValue bool
	if len(queries) == 2 {
		value = queries[1]
		hasValue = true
	}

	tree.matcher = func(req *routing.Request) bool {
		if req.Query == nil {
			return false
		}

		values, ok := req.Query[key]
		if !ok {
			return false
		}

		if !hasValue {
			return true
		}

		return slices.Contains(values, value)
	}

	return nil
}

func queryRegexp(tree *matchersTree, queries ...string) error {
	if len(queries) == 1 {
		return query(tree, queries...)
	}

	key, value := queries[0], queries[1]

	re, err := regexp.Compile(value)
	if err != nil {
		return fmt.Errorf("compiling QueryRegexp matcher: %w", err)
	}

	tree.matcher = func(req *routing.Request) bool {
		if req.Query == nil {
			return false
		}

		values, ok := req.Query[key]
		if !ok {
			return false
		}

		idx := slices.IndexFunc(values, func(value string) bool {
			return re.MatchString(value)
		})

		return idx >= 0
	}

	return nil
}

// IsASCII checks if the given string contains only ASCII characters.
func IsASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}

func parseHost(addr string) string {
	if !strings.Contains(addr, ":") {
		// IPv4 without port or empty address
		return addr
	}

	// IPv4 with port or IPv6
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if addr[0] == '[' && addr[len(addr)-1] == ']' {
			return addr[1 : len(addr)-1]
		}
		return addr
	}
	return host
}
