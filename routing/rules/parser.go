package rules

import (
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"strconv"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	and = "and"
	or  = "or"
)

// Parser parses a routing rule expression into a TreeBuilder.
type Parser interface {
	Parse(string) (interface{}, error)
}

// TreeBuilder defines the type for a Tree builder.
type TreeBuilder func() *Tree

// Tree represents the rules' tree structure used for routing matchers.
// Leaf nodes hold a Matcher name, optional negation, and string values.
// Internal nodes hold an "and"/"or" operator with left and right children.
type Tree struct {
	Matcher   string
	Not       bool
	Value     []string
	RuleLeft  *Tree
	RuleRight *Tree
}

// NewParser constructs a parser for the given matchers.
//
// Rules are parsed as Go expressions via go/parser, so each matcher is
// registered under every case variant (exact, lower, upper, title) to make
// matching case-insensitive. The canonical matcher name (as given) is what
// ends up in the resulting Tree.
func NewParser(matchers []string) (Parser, error) {
	names := make(map[string]string, 4*len(matchers))
	for _, name := range matchers {
		names[name] = name
		names[strings.ToLower(name)] = name
		names[strings.ToUpper(name)] = name
		names[cases.Title(language.Und).String(strings.ToLower(name))] = name
	}
	return &parser{names: names}, nil
}

// parser turns a rule such as `Host("example.com") && !Path("/api")` into a
// Tree. It reimplements the subset of the previous dependency
// (vulcand/predicate) needed here, so that x no longer pulls in the
// predicate -> trace -> logrus dependency chain.
type parser struct {
	names map[string]string
}

func (p *parser) Parse(rule string) (interface{}, error) {
	expr, err := goparser.ParseExpr(rule)
	if err != nil {
		return nil, err
	}

	tree, err := p.build(expr)
	if err != nil {
		return nil, err
	}

	return TreeBuilder(func() *Tree { return tree }), nil
}

// build converts an expression into its Tree.
func (p *parser) build(expr ast.Expr) (*Tree, error) {
	switch n := expr.(type) {
	case *ast.BinaryExpr:
		left, err := p.build(n.X)
		if err != nil {
			return nil, err
		}
		right, err := p.build(n.Y)
		if err != nil {
			return nil, err
		}
		return combine(n.Op, left, right)

	case *ast.ParenExpr:
		return p.build(n.X)

	case *ast.UnaryExpr:
		if n.Op != token.NOT {
			return nil, fmt.Errorf("unsupported operator %v", n.Op)
		}
		child, err := p.build(n.X)
		if err != nil {
			return nil, err
		}
		return invert(child), nil

	case *ast.CallExpr:
		ident, ok := n.Fun.(*ast.Ident)
		if !ok {
			return nil, fmt.Errorf("expected matcher identifier, got %T", n.Fun)
		}
		name, ok := p.names[ident.Name]
		if !ok {
			return nil, fmt.Errorf("unsupported matcher: %s", ident.Name)
		}

		values := make([]string, 0, len(n.Args))
		for _, arg := range n.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return nil, fmt.Errorf("unsupported argument %v for matcher %s", arg, name)
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}

		return &Tree{
			Matcher: name,
			Value:   values,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported expression %T", expr)
	}
}

func combine(op token.Token, left, right *Tree) (*Tree, error) {
	switch op {
	case token.LAND:
		return &Tree{Matcher: and, RuleLeft: left, RuleRight: right}, nil
	case token.LOR:
		return &Tree{Matcher: or, RuleLeft: left, RuleRight: right}, nil
	default:
		return nil, fmt.Errorf("unsupported operator %v", op)
	}
}

// invert returns a new Tree applying De Morgan's law: each internal node's
// and/or is swapped and every leaf's Not flag is toggled. It never mutates
// its input.
func invert(t *Tree) *Tree {
	n := *t
	switch n.Matcher {
	case and:
		n.Matcher = or
	case or:
		n.Matcher = and
	default:
		n.Not = !n.Not
	}
	if n.RuleLeft != nil {
		n.RuleLeft = invert(n.RuleLeft)
	}
	if n.RuleRight != nil {
		n.RuleRight = invert(n.RuleRight)
	}
	return &n
}

// ParseMatchers returns the subset of values in the Tree matching the given
// matchers.
func (tree *Tree) ParseMatchers(matchers []string) []string {
	switch tree.Matcher {
	case and, or:
		return append(tree.RuleLeft.ParseMatchers(matchers), tree.RuleRight.ParseMatchers(matchers)...)
	default:
		for _, matcher := range matchers {
			if tree.Matcher == matcher {
				return lower(tree.Value)
			}
		}
		return nil
	}
}

// CheckRule validates the given rule.
func CheckRule(rule *Tree) error {
	if len(rule.Value) == 0 {
		return fmt.Errorf("no args for matcher %s", rule.Matcher)
	}
	for _, v := range rule.Value {
		if len(v) == 0 {
			return fmt.Errorf("empty args for matcher %s, %v", rule.Matcher, rule.Value)
		}
	}
	return nil
}

func lower(slice []string) []string {
	var lowerStrings []string
	for _, value := range slice {
		lowerStrings = append(lowerStrings, strings.ToLower(value))
	}
	return lowerStrings
}
