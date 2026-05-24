package metadata

import (
	"testing"

	"github.com/go-gost/core/metadata"
)

func TestNewMetadata(t *testing.T) {
	md := NewMetadata(map[string]any{"Key": "val", "FOO": "bar"})
	if md == nil {
		t.Fatal("NewMetadata returned nil")
	}

	if !md.IsExists("key") {
		t.Error("key not found")
	}
	if !md.IsExists("KEY") {
		t.Error("KEY not found (case-insensitive)")
	}
	if !md.IsExists("foo") {
		t.Error("foo not found")
	}
	if md.IsExists("baz") {
		t.Error("baz should not exist")
	}
}

func TestNewMetadata_Nil(t *testing.T) {
	md := NewMetadata(nil)
	if md == nil {
		t.Fatal("NewMetadata(nil) returned nil — expected empty Metadata")
	}
	if md.IsExists("any") {
		t.Error("empty metadata should have no keys")
	}
}

func TestNewMetadata_Empty(t *testing.T) {
	md := NewMetadata(map[string]any{})
	if md == nil {
		t.Fatal("NewMetadata(empty) returned nil")
	}
	if md.IsExists("any") {
		t.Error("empty metadata should have no keys")
	}
}

func TestMapMetadata_IsExists(t *testing.T) {
	md := NewMetadata(map[string]any{"foo": "bar"}).(mapMetadata)
	if !md.IsExists("foo") {
		t.Error("IsExists(foo) should be true")
	}
	if !md.IsExists("FOO") {
		t.Error("IsExists(FOO) should be true (case-insensitive)")
	}
	if md.IsExists("bar") {
		t.Error("IsExists(bar) should be false")
	}
}

func TestMapMetadata_Get(t *testing.T) {
	md := NewMetadata(map[string]any{"foo": "bar", "num": 42}).(mapMetadata)

	if v := md.Get("foo"); v != "bar" {
		t.Errorf("Get(foo) = %v, want bar", v)
	}
	if v := md.Get("FOO"); v != "bar" {
		t.Errorf("Get(FOO) = %v, want bar (case-insensitive)", v)
	}
	if v := md.Get("num"); v != 42 {
		t.Errorf("Get(num) = %v, want 42", v)
	}
	if v := md.Get("baz"); v != nil {
		t.Errorf("Get(baz) = %v, want nil", v)
	}
}

func TestMapMetadata_Get_NilReceiver(t *testing.T) {
	var m mapMetadata
	if v := m.Get("foo"); v != nil {
		t.Errorf("Get on nil mapMetadata = %v, want nil", v)
	}
}

func TestMapMetadata_IsExists_NilReceiver(t *testing.T) {
	var m mapMetadata
	if m.IsExists("foo") {
		t.Error("IsExists on nil mapMetadata should be false")
	}
}

func TestMapMetadata_Set(t *testing.T) {
	md := NewMetadata(nil).(mapMetadata)
	md.Set("foo", "bar")
	if !md.IsExists("foo") {
		t.Error("IsExists(foo) should be true after Set")
	}
	if v := md.Get("foo"); v != "bar" {
		t.Errorf("Get(foo) = %v, want bar", v)
	}
}

func TestMapMetadata_Set_CaseInsensitive(t *testing.T) {
	md := NewMetadata(nil).(mapMetadata)
	md.Set("FOO", "bar")
	if v := md.Get("foo"); v != "bar" {
		t.Errorf("Get(foo) after Set(FOO) = %v, want bar", v)
	}
}

func TestMapMetadata_Set_Overwrite(t *testing.T) {
	md := NewMetadata(map[string]any{"foo": "old"}).(mapMetadata)
	md.Set("FOO", "new")
	if v := md.Get("foo"); v != "new" {
		t.Errorf("Get(foo) after overwrite = %v, want new", v)
	}
}

func TestInterfaceCompliance(t *testing.T) {
	var _ metadata.Metadata = NewMetadata(nil)
	var _ metadata.Metadata = mapMetadata(nil)
}
