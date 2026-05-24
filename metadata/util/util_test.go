package util

import (
	"testing"
	"time"

	"github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

func TestIsExists(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{"foo": "bar"})
	if !IsExists(md, "foo") {
		t.Error("IsExists(foo) should be true")
	}
	if IsExists(md, "bar") {
		t.Error("IsExists(bar) should be false")
	}
	if !IsExists(md, "BAR", "foo") {
		t.Error("IsExists(BAR, foo): foo exists, should return true")
	}
}

func TestIsExists_TrueWithFallback(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{"foo": "bar"})
	if !IsExists(md, "bar", "foo") {
		t.Error("IsExists(bar, foo): foo exists, should return true")
	}
	if IsExists(md, "bar", "baz") {
		t.Error("IsExists(bar, baz): neither exists, should return false")
	}
}

func TestIsExists_Nil(t *testing.T) {
	if IsExists(nil, "foo") {
		t.Error("IsExists on nil Metadata should be false")
	}
}

func TestGetBool(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"b":   true,
		"i":   1,
		"i0":  0,
		"s":   "true",
		"s2":  "false",
		"bad": "notabool",
	})
	if v := GetBool(md, "b"); v != true {
		t.Errorf("GetBool(b) = %v, want true", v)
	}
	if v := GetBool(md, "i"); v != true {
		t.Errorf("GetBool(i=1) = %v, want true", v)
	}
	if v := GetBool(md, "i0"); v != false {
		t.Errorf("GetBool(i=0) = %v, want false", v)
	}
	if v := GetBool(md, "s"); v != true {
		t.Errorf("GetBool(s=true) = %v, want true", v)
	}
	if v := GetBool(md, "s2"); v != false {
		t.Errorf("GetBool(s=false) = %v, want false", v)
	}
	if v := GetBool(md, "bad"); v != false {
		t.Errorf("GetBool(bad) = %v, want false (parse error)", v)
	}
}

func TestGetBool_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{})
	if v := GetBool(md, "nonexistent"); v != false {
		t.Errorf("GetBool(nonexistent) = %v, want false", v)
	}
}

func TestGetBool_Nil(t *testing.T) {
	if v := GetBool(nil, "foo"); v != false {
		t.Errorf("GetBool on nil = %v, want false", v)
	}
}

func TestGetInt(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"i":  42,
		"s":  "99",
		"b":  true,
		"bf": false,
		"bad": "notanumber",
	})
	if v := GetInt(md, "i"); v != 42 {
		t.Errorf("GetInt(i) = %v, want 42", v)
	}
	if v := GetInt(md, "s"); v != 99 {
		t.Errorf("GetInt(s) = %v, want 99", v)
	}
	if v := GetInt(md, "b"); v != 1 {
		t.Errorf("GetInt(b=true) = %v, want 1", v)
	}
	if v := GetInt(md, "bf"); v != 0 {
		t.Errorf("GetInt(bf=false) = %v, want 0", v)
	}
	if v := GetInt(md, "bad"); v != 0 {
		t.Errorf("GetInt(bad) = %v, want 0", v)
	}
}

func TestGetInt_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(nil)
	if v := GetInt(md, "nonexistent"); v != 0 {
		t.Errorf("GetInt(nonexistent) = %v, want 0", v)
	}
}

func TestGetInt_Nil(t *testing.T) {
	if v := GetInt(nil, "foo"); v != 0 {
		t.Errorf("GetInt on nil = %v, want 0", v)
	}
}

func TestGetFloat(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"f64":  float64(3.14),
		"f32":  float32(2.5),
		"i":    42,
		"s":    "1.5",
		"bad":  "notanumber",
	})
	if v := GetFloat(md, "f64"); v != 3.14 {
		t.Errorf("GetFloat(f64) = %v, want 3.14", v)
	}
	if v := GetFloat(md, "f32"); v != 2.5 {
		t.Errorf("GetFloat(f32) = %v, want 2.5", v)
	}
	if v := GetFloat(md, "i"); v != 42.0 {
		t.Errorf("GetFloat(i) = %v, want 42.0", v)
	}
	if v := GetFloat(md, "s"); v != 1.5 {
		t.Errorf("GetFloat(s) = %v, want 1.5", v)
	}
	if v := GetFloat(md, "bad"); v != 0 {
		t.Errorf("GetFloat(bad) = %v, want 0", v)
	}
}

func TestGetFloat_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(nil)
	if v := GetFloat(md, "nonexistent"); v != 0 {
		t.Errorf("GetFloat(nonexistent) = %v, want 0", v)
	}
}

func TestGetFloat_Nil(t *testing.T) {
	if v := GetFloat(nil, "foo"); v != 0 {
		t.Errorf("GetFloat on nil = %v, want 0", v)
	}
}

func TestGetDuration(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"ds":  "5s",
		"dms": "100ms",
		"di":  30,
		"dis": "60",
		"bad": "notaduration",
	})
	if v := GetDuration(md, "ds"); v != 5*time.Second {
		t.Errorf("GetDuration(5s) = %v, want %v", v, 5*time.Second)
	}
	if v := GetDuration(md, "dms"); v != 100*time.Millisecond {
		t.Errorf("GetDuration(100ms) = %v, want %v", v, 100*time.Millisecond)
	}
	if v := GetDuration(md, "di"); v != 30*time.Second {
		t.Errorf("GetDuration(30) = %v, want %v", v, 30*time.Second)
	}
	if v := GetDuration(md, "dis"); v != 60*time.Second {
		t.Errorf("GetDuration(\"60\") = %v, want %v", v, 60*time.Second)
	}
	if v := GetDuration(md, "bad"); v != 0 {
		t.Errorf("GetDuration(bad) = %v, want 0", v)
	}
}

func TestGetDuration_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(nil)
	if v := GetDuration(md, "nonexistent"); v != 0 {
		t.Errorf("GetDuration(nonexistent) = %v, want 0", v)
	}
}

func TestGetDuration_Nil(t *testing.T) {
	if v := GetDuration(nil, "foo"); v != 0 {
		t.Errorf("GetDuration on nil = %v, want 0", v)
	}
}

func TestGetString(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"s":   "hello",
		"i":   42,
		"i64": int64(99),
		"u":   uint(7),
		"u64": uint64(100),
		"b":   true,
		"f32": float32(3.14),
		"f64": float64(2.718),
	})
	if v := GetString(md, "s"); v != "hello" {
		t.Errorf("GetString(s) = %q, want hello", v)
	}
	if v := GetString(md, "i"); v != "42" {
		t.Errorf("GetString(i) = %q, want 42", v)
	}
	if v := GetString(md, "i64"); v != "99" {
		t.Errorf("GetString(i64) = %q, want 99", v)
	}
	if v := GetString(md, "u"); v != "7" {
		t.Errorf("GetString(u) = %q, want 7", v)
	}
	if v := GetString(md, "u64"); v != "100" {
		t.Errorf("GetString(u64) = %q, want 100", v)
	}
	if v := GetString(md, "b"); v != "true" {
		t.Errorf("GetString(b) = %q, want true", v)
	}
	if v := GetString(md, "f32"); v != "3.14" {
		t.Errorf("GetString(f32) = %q, want 3.14", v)
	}
	if v := GetString(md, "f64"); v != "2.718" {
		t.Errorf("GetString(f64) = %q, want 2.718", v)
	}
}

func TestGetString_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(nil)
	if v := GetString(md, "nonexistent"); v != "" {
		t.Errorf("GetString(nonexistent) = %q, want empty", v)
	}
}

func TestGetString_Nil(t *testing.T) {
	if v := GetString(nil, "foo"); v != "" {
		t.Errorf("GetString on nil = %q, want empty", v)
	}
}

func TestGetStrings(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"ss": []string{"a", "b", "c"},
		"sa": []any{"x", "y", "z"},
		"mixed": []any{"hello", 42, "world"},
	})
	if v := GetStrings(md, "ss"); len(v) != 3 || v[0] != "a" || v[1] != "b" || v[2] != "c" {
		t.Errorf("GetStrings(ss) = %v, want [a b c]", v)
	}
	if v := GetStrings(md, "sa"); len(v) != 3 || v[0] != "x" || v[1] != "y" || v[2] != "z" {
		t.Errorf("GetStrings(sa) = %v, want [x y z]", v)
	}
	if v := GetStrings(md, "mixed"); len(v) != 2 || v[0] != "hello" || v[1] != "world" {
		t.Errorf("GetStrings(mixed) = %v, want [hello world]", v)
	}
}

func TestGetStrings_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(nil)
	if v := GetStrings(md, "nonexistent"); v != nil {
		t.Errorf("GetStrings(nonexistent) = %v, want nil", v)
	}
}

func TestGetStrings_Nil(t *testing.T) {
	if v := GetStrings(nil, "foo"); v != nil {
		t.Errorf("GetStrings on nil = %v, want nil", v)
	}
}

func TestGetStringMap(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"m": map[string]any{"k1": "v1", "k2": 42},
		"a": map[any]any{"x": "y", 1: "one"},
	})
	m := GetStringMap(md, "m")
	if m["k1"] != "v1" {
		t.Errorf("m[k1] = %v, want v1", m["k1"])
	}
	if m["k2"] != 42 {
		t.Errorf("m[k2] = %v, want 42", m["k2"])
	}

	a := GetStringMap(md, "a")
	if a["x"] != "y" {
		t.Errorf("a[x] = %v, want y", a["x"])
	}
	if a["1"] != "one" {
		t.Errorf("a[1] = %v, want one", a["1"])
	}
}

func TestGetStringMap_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(nil)
	if v := GetStringMap(md, "nonexistent"); v != nil {
		t.Errorf("GetStringMap(nonexistent) = %v, want nil", v)
	}
}

func TestGetStringMap_Nil(t *testing.T) {
	if v := GetStringMap(nil, "foo"); v != nil {
		t.Errorf("GetStringMap on nil = %v, want nil", v)
	}
}

func TestGetStringMapString(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"m": map[string]any{"k1": "v1", "k2": 42},
		"a": map[any]any{"x": "y", 1: "one"},
	})
	m := GetStringMapString(md, "m")
	if m["k1"] != "v1" {
		t.Errorf("m[k1] = %v, want v1", m["k1"])
	}
	if m["k2"] != "42" {
		t.Errorf("m[k2] = %v, want 42", m["k2"])
	}

	a := GetStringMapString(md, "a")
	if a["x"] != "y" {
		t.Errorf("a[x] = %v, want y", a["x"])
	}
	if a["1"] != "one" {
		t.Errorf("a[1] = %v, want one", a["1"])
	}
}

func TestGetStringMapString_MissingKey(t *testing.T) {
	md := mdx.NewMetadata(nil)
	if v := GetStringMapString(md, "nonexistent"); v != nil {
		t.Errorf("GetStringMapString(nonexistent) = %v, want nil", v)
	}
}

func TestGetStringMapString_Nil(t *testing.T) {
	if v := GetStringMapString(nil, "foo"); v != nil {
		t.Errorf("GetStringMapString on nil = %v, want nil", v)
	}
}

func TestFallbackKeys(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"second": "fallback-val",
	})
	if v := GetString(md, "first", "second"); v != "fallback-val" {
		t.Errorf("GetString with fallback = %q, want fallback-val", v)
	}
	if v := GetBool(md, "first", "second"); v != false {
		t.Errorf("GetBool: string should not match bool fallback, got %v", v)
	}
}

func TestFallbackKeys_FirstWins(t *testing.T) {
	md := mdx.NewMetadata(map[string]any{
		"first":  "winner",
		"second": "loser",
	})
	if v := GetString(md, "first", "second"); v != "winner" {
		t.Errorf("GetString(first, second) = %q, want winner", v)
	}
}

// Ensure nil interface (not just nil mapMetadata) works for all functions.
func TestNilInterface(t *testing.T) {
	var md metadata.Metadata
	if IsExists(md, "foo") {
		t.Error("IsExists on nil Metadata interface should be false")
	}
	if GetBool(md, "foo") {
		t.Error("GetBool on nil Metadata interface should be false")
	}
	if GetInt(md, "foo") != 0 {
		t.Error("GetInt on nil Metadata interface should be 0")
	}
	if GetFloat(md, "foo") != 0 {
		t.Error("GetFloat on nil Metadata interface should be 0")
	}
	if GetDuration(md, "foo") != 0 {
		t.Error("GetDuration on nil Metadata interface should be 0")
	}
	if GetString(md, "foo") != "" {
		t.Error("GetString on nil Metadata interface should be empty")
	}
	if GetStrings(md, "foo") != nil {
		t.Error("GetStrings on nil Metadata interface should be nil")
	}
	if GetStringMap(md, "foo") != nil {
		t.Error("GetStringMap on nil Metadata interface should be nil")
	}
	if GetStringMapString(md, "foo") != nil {
		t.Error("GetStringMapString on nil Metadata interface should be nil")
	}
}
