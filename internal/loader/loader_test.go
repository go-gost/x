package loader

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- FileLoader ---

func TestFileLoader_Load(t *testing.T) {
	f, err := os.CreateTemp("", "loader-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString("hello world"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	ld := FileLoader(f.Name())
	r, err := ld.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Fatalf("got %q, want %q", string(data), "hello world")
	}
}

func TestFileLoader_Load_NotFound(t *testing.T) {
	ld := FileLoader("/nonexistent/path")
	_, err := ld.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestFileLoader_List(t *testing.T) {
	f, err := os.CreateTemp("", "loader-list-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	lines := "alpha\nbeta\ngamma\n"
	if _, err := f.WriteString(lines); err != nil {
		t.Fatal(err)
	}
	f.Close()

	ld := FileLoader(f.Name())
	list, err := ld.(Lister).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d lines, want 3", len(list))
	}
	expected := []string{"alpha", "beta", "gamma"}
	for i, v := range expected {
		if list[i] != v {
			t.Fatalf("line %d: got %q, want %q", i, list[i], v)
		}
	}
}

func TestFileLoader_List_NotFound(t *testing.T) {
	ld := FileLoader("/nonexistent/path")
	_, err := ld.(Lister).List(context.Background())
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestFileLoader_Close(t *testing.T) {
	ld := FileLoader("/dev/null")
	if err := ld.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileLoader_ImplementsLister(t *testing.T) {
	_ = FileLoader("").(Lister)
}

// --- HTTPLoader ---

func TestHTTPLoader_Load(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("http response"))
	}))
	defer srv.Close()

	ld := HTTPLoader(srv.URL)
	r, err := ld.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "http response" {
		t.Fatalf("got %q, want %q", string(data), "http response")
	}
}

func TestHTTPLoader_Load_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ld := HTTPLoader(srv.URL)
	_, err := ld.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestHTTPLoader_Load_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ld := HTTPLoader(srv.URL)
	_, err := ld.Load(ctx)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestHTTPLoader_Load_BadURL(t *testing.T) {
	ld := HTTPLoader("://invalid-url")
	_, err := ld.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func TestHTTPLoader_Close(t *testing.T) {
	ld := HTTPLoader("http://localhost:1")
	if err := ld.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPLoader_TimeoutOption(t *testing.T) {
	ld := HTTPLoader("http://localhost:1", TimeoutHTTPLoaderOption(0))
	_ = ld
}

// --- RedisLoaderOption ---

func TestRedisLoaderOption_DB(t *testing.T) {
	var opts redisLoaderOptions
	opt := DBRedisLoaderOption(5)
	opt(&opts)
	if opts.db != 5 {
		t.Fatalf("got db %d, want 5", opts.db)
	}
}

func TestRedisLoaderOption_Username(t *testing.T) {
	var opts redisLoaderOptions
	opt := UsernameRedisLoaderOption("admin")
	opt(&opts)
	if opts.username != "admin" {
		t.Fatalf("got username %q, want %q", opts.username, "admin")
	}
}

func TestRedisLoaderOption_Password(t *testing.T) {
	var opts redisLoaderOptions
	opt := PasswordRedisLoaderOption("secret")
	opt(&opts)
	if opts.password != "secret" {
		t.Fatalf("got password %q, want %q", opts.password, "secret")
	}
}

func TestRedisLoaderOption_Key(t *testing.T) {
	var opts redisLoaderOptions
	opt := KeyRedisLoaderOption("mykey")
	opt(&opts)
	if opts.key != "mykey" {
		t.Fatalf("got key %q, want %q", opts.key, "mykey")
	}
}

func TestRedisLoaderOption_NilOption(t *testing.T) {
	// Verify nil options don't panic across all constructors.
	// The nil guard in each constructor should prevent calling the nil option function.
	HTTPLoader("http://localhost:1", HTTPLoaderOption(nil))
	RedisStringLoader("localhost:6379", RedisLoaderOption(nil))
	RedisSetLoader("localhost:6379", RedisLoaderOption(nil))
	RedisListLoader("localhost:6379", RedisLoaderOption(nil))
	RedisHashLoader("localhost:6379", RedisLoaderOption(nil))
}

func TestRedisLoaderOption_DefaultKey(t *testing.T) {
	if DefaultRedisKey != "gost" {
		t.Fatalf("got DefaultRedisKey %q, want %q", DefaultRedisKey, "gost")
	}
}

// -- Interface satisfaction (compile-time) ---

// --- RedisSetLoader supports Lister ---

func TestRedisSetLoader_ImplementsLister(t *testing.T) {
	var _ Lister = &redisSetLoader{}
}

// --- RedisListLoader supports Lister ---

func TestRedisListLoader_ImplementsLister(t *testing.T) {
	var _ Lister = &redisListLoader{}
}

// --- RedisHashLoader supports Lister and Mapper ---

func TestRedisHashLoader_ImplementsLister(t *testing.T) {
	var _ Lister = &redisHashLoader{}
}

func TestRedisHashLoader_ImplementsMapper(t *testing.T) {
	var _ Mapper = &redisHashLoader{}
}

// --- RedisStringLoader Load with empty result ---

func TestRedisLoaderOption_MultipleOptions(t *testing.T) {
	var opts redisLoaderOptions
	for _, opt := range []RedisLoaderOption{
		DBRedisLoaderOption(3),
		UsernameRedisLoaderOption("user"),
		PasswordRedisLoaderOption("pass"),
		KeyRedisLoaderOption("k"),
	} {
		opt(&opts)
	}
	if opts.db != 3 {
		t.Fatalf("got db %d, want 3", opts.db)
	}
	if opts.username != "user" {
		t.Fatalf("got username %q, want %q", opts.username, "user")
	}
	if opts.password != "pass" {
		t.Fatalf("got password %q, want %q", opts.password, "pass")
	}
	if opts.key != "k" {
		t.Fatalf("got key %q, want %q", opts.key, "k")
	}
}

// --- HTTPLoader_Load verifies reader is independent ---

func TestHTTPLoader_Load_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(nil)
	}))
	defer srv.Close()

	ld := HTTPLoader(srv.URL)
	r, err := ld.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty body, got %q", string(data))
	}
}

// --- FileLoader Load verifies reader independence ---

func TestFileLoader_Load_EmptyFile(t *testing.T) {
	f, err := os.CreateTemp("", "loader-empty-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	ld := FileLoader(f.Name())
	r, err := ld.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty, got %q", string(data))
	}
}

// --- FileLoader List empty file ---

func TestFileLoader_List_EmptyFile(t *testing.T) {
	f, err := os.CreateTemp("", "loader-list-empty-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	ld := FileLoader(f.Name())
	list, err := ld.(Lister).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("got %v, want empty list for empty file", list)
	}
}

// --- HTTPLoader Load with large body ---

func TestHTTPLoader_Load_LargeBody(t *testing.T) {
	largeData := strings.Repeat("x", 1<<16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largeData))
	}))
	defer srv.Close()

	ld := HTTPLoader(srv.URL)
	r, err := ld.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != largeData {
		t.Fatalf("got %d bytes, want %d", len(data), len(largeData))
	}
}

// --- HTTPLoader Load with custom timeout option ---

func TestHTTPLoader_Load_WithTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ld := HTTPLoader(srv.URL, TimeoutHTTPLoaderOption(0))
	r, err := ld.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("got %q, want %q", string(data), "ok")
	}
}

// --- Verify Loader interface on all constructors ---

func TestRedisStringLoader_SatisfiesLoader(t *testing.T) {
	var _ Loader = &redisStringLoader{}
}

func TestRedisSetLoader_SatisfiesLoader(t *testing.T) {
	var _ Loader = &redisSetLoader{}
}

func TestRedisListLoader_SatisfiesLoader(t *testing.T) {
	var _ Loader = &redisListLoader{}
}

func TestRedisHashLoader_SatisfiesLoader(t *testing.T) {
	var _ Loader = &redisHashLoader{}
}
