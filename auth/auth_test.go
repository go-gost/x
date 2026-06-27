package auth

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
)

// --- mock types ---

type mockLoader struct {
	loadData string
	loadErr  error
	closed   bool
}

func (m *mockLoader) Load(ctx context.Context) (io.Reader, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return strings.NewReader(m.loadData), nil
}

func (m *mockLoader) Close() error {
	m.closed = true
	return nil
}

type mockMapper struct {
	mapData map[string]string
	mapErr  error
	closed  bool
}

func (m *mockMapper) Load(ctx context.Context) (io.Reader, error) {
	return nil, nil
}

func (m *mockMapper) Map(ctx context.Context) (map[string]string, error) {
	if m.mapErr != nil {
		return nil, m.mapErr
	}
	return m.mapData, nil
}

func (m *mockMapper) Close() error {
	m.closed = true
	return nil
}

var _ loader.Loader = (*mockLoader)(nil)
var _ loader.Loader = (*mockMapper)(nil)
var _ loader.Mapper = (*mockMapper)(nil)

// --- option tests ---

func TestAuthsOption(t *testing.T) {
	opts := &options{}
	auths := map[string]string{"user": "pass"}
	AuthsOption(auths)(opts)
	if len(opts.auths) != 1 || opts.auths["user"] != "pass" {
		t.Fatalf("expected auths to be set, got %v", opts.auths)
	}
}

func TestReloadPeriodOption(t *testing.T) {
	opts := &options{}
	ReloadPeriodOption(5 * time.Second)(opts)
	if opts.period != 5*time.Second {
		t.Fatalf("expected period 5s, got %v", opts.period)
	}
}

func TestFileLoaderOption(t *testing.T) {
	opts := &options{}
	ml := &mockLoader{}
	FileLoaderOption(ml)(opts)
	if opts.fileLoader != ml {
		t.Fatal("expected fileLoader to be set")
	}
}

func TestRedisLoaderOption(t *testing.T) {
	opts := &options{}
	ml := &mockLoader{}
	RedisLoaderOption(ml)(opts)
	if opts.redisLoader != ml {
		t.Fatal("expected redisLoader to be set")
	}
}

func TestHTTPLoaderOption(t *testing.T) {
	opts := &options{}
	ml := &mockLoader{}
	HTTPLoaderOption(ml)(opts)
	if opts.httpLoader != ml {
		t.Fatal("expected httpLoader to be set")
	}
}

func TestLoggerOption(t *testing.T) {
	opts := &options{}
	l := xlogger.Nop()
	LoggerOption(l)(opts)
	if opts.logger != l {
		t.Fatal("expected logger to be set")
	}
}

// --- NewAuthenticator tests ---

func TestNewAuthenticator_Defaults(t *testing.T) {
	p := NewAuthenticator()
	if p == nil {
		t.Fatal("expected authenticator to be created")
	}
	defer p.(*authenticator).Close()

	ap := p.(*authenticator)
	if ap.logger == nil {
		t.Fatal("expected non-nil logger (Nop fallback)")
	}
	if ap.cancelFunc == nil {
		t.Fatal("expected cancelFunc to be set")
	}
	if len(ap.kvs) != 0 {
		t.Fatal("expected empty kvs")
	}
}

func TestNewAuthenticator_WithAuths(t *testing.T) {
	p := NewAuthenticator(AuthsOption(map[string]string{"u": "p"}))
	defer p.(*authenticator).Close()

	// Initial reload is async — wait for it.
	time.Sleep(50 * time.Millisecond)

	ap := p.(*authenticator)
	ap.mu.RLock()
	if ap.kvs["u"] != "p" {
		t.Fatal("expected kvs to contain u=p")
	}
	ap.mu.RUnlock()
}

func TestNewAuthenticator_WithLogger(t *testing.T) {
	l := xlogger.Nop()
	p := NewAuthenticator(LoggerOption(l))
	defer p.(*authenticator).Close()

	ap := p.(*authenticator)
	if ap.logger != l {
		t.Fatal("expected custom logger")
	}
}

// --- Authenticate tests ---

func TestAuthenticate_NilReceiver(t *testing.T) {
	var p *authenticator
	id, ok := p.Authenticate(context.Background(), "u", "p")
	if !ok || id != "" {
		t.Fatalf("nil receiver should return '', true, got %q, %v", id, ok)
	}
}

func TestAuthenticate_EmptyKVs(t *testing.T) {
	p := NewAuthenticator()
	defer p.(*authenticator).Close()

	id, ok := p.Authenticate(context.Background(), "u", "p")
	if ok || id != "" {
		t.Fatalf("empty kvs should return '', false, got %q, %v", id, ok)
	}
}

func TestAuthenticate_UserNotFound(t *testing.T) {
	p := NewAuthenticator(AuthsOption(map[string]string{"admin": "secret"}))
	defer p.(*authenticator).Close()

	// Wait for initial reload to populate kvs
	time.Sleep(50 * time.Millisecond)

	// When user is not in kvs, Authenticate returns (user, false)
	id, ok := p.Authenticate(context.Background(), "nobody", "")
	if ok || id != "nobody" {
		t.Fatalf("unknown user should return 'nobody', false, got %q, %v", id, ok)
	}
}

func TestAuthenticate_UserFoundNoPassword(t *testing.T) {
	p := NewAuthenticator(AuthsOption(map[string]string{"open": ""}))
	defer p.(*authenticator).Close()

	time.Sleep(50 * time.Millisecond)

	id, ok := p.Authenticate(context.Background(), "open", "")
	if !ok || id != "open" {
		t.Fatalf("expected open, true, got %q, %v", id, ok)
	}
	id2, ok2 := p.Authenticate(context.Background(), "open", "anything")
	if !ok2 || id2 != "open" {
		t.Fatalf("any password should pass for empty-password user, got %q, %v", id2, ok2)
	}
}

func TestAuthenticate_PasswordMatch(t *testing.T) {
	p := NewAuthenticator(AuthsOption(map[string]string{"admin": "secret"}))
	defer p.(*authenticator).Close()

	time.Sleep(50 * time.Millisecond)

	id, ok := p.Authenticate(context.Background(), "admin", "secret")
	if !ok || id != "admin" {
		t.Fatalf("expected admin, true, got %q, %v", id, ok)
	}
}

func TestAuthenticate_PasswordMismatch(t *testing.T) {
	p := NewAuthenticator(AuthsOption(map[string]string{"admin": "secret"}))
	defer p.(*authenticator).Close()

	time.Sleep(50 * time.Millisecond)

	id, ok := p.Authenticate(context.Background(), "admin", "wrong")
	if ok {
		t.Fatalf("wrong password should return false, got %q, %v", id, ok)
	}
}

// --- parseAuths tests ---

func TestParseAuths_NilReader(t *testing.T) {
	p := &authenticator{}
	result, err := p.parseAuths(nil)
	if err != nil || result != nil {
		t.Fatalf("nil reader should return nil, nil, got %v, %v", result, err)
	}
}

func TestParseAuths_EmptyReader(t *testing.T) {
	p := &authenticator{}
	result, err := p.parseAuths(strings.NewReader(""))
	if err != nil || len(result) != 0 {
		t.Fatalf("empty reader should return empty map, got %v, %v", result, err)
	}
}

func TestParseAuths_Comments(t *testing.T) {
	p := &authenticator{}
	result, err := p.parseAuths(strings.NewReader("# this is a comment\n# another comment"))
	if err != nil || len(result) != 0 {
		t.Fatalf("comments should be skipped, got %v, %v", result, err)
	}
}

func TestParseAuths_SingleKey(t *testing.T) {
	p := &authenticator{}
	result, err := p.parseAuths(strings.NewReader("testuser"))
	if err != nil {
		t.Fatal(err)
	}
	if result["testuser"] != "" {
		t.Fatalf("single key should have empty password, got %q", result["testuser"])
	}
}

func TestParseAuths_KeyValue(t *testing.T) {
	p := &authenticator{}
	result, err := p.parseAuths(strings.NewReader("testuser testpass"))
	if err != nil {
		t.Fatal(err)
	}
	if result["testuser"] != "testpass" {
		t.Fatalf("expected testpass, got %q", result["testuser"])
	}
}

func TestParseAuths_TabConversion(t *testing.T) {
	p := &authenticator{}
	result, err := p.parseAuths(strings.NewReader("testuser\ttestpass"))
	if err != nil {
		t.Fatal(err)
	}
	if result["testuser"] != "testpass" {
		t.Fatalf("tab should be converted to space, got %q", result["testuser"])
	}
}

func TestParseAuths_MultipleLines(t *testing.T) {
	p := &authenticator{}
	data := "user1 pass1\nuser2\nuser3 pass3\n# comment\n\n  user4  pass4  "
	result, err := p.parseAuths(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(result))
	}
	if result["user1"] != "pass1" {
		t.Fatalf("user1: expected pass1, got %q", result["user1"])
	}
	if result["user2"] != "" {
		t.Fatalf("user2: expected empty, got %q", result["user2"])
	}
	if result["user3"] != "pass3" {
		t.Fatalf("user3: expected pass3, got %q", result["user3"])
	}
	if result["user4"] != "pass4" {
		t.Fatalf("user4: expected pass4, got %q", result["user4"])
	}
}

func TestParseAuths_EmptyKeyInPair(t *testing.T) {
	p := &authenticator{}
	result, err := p.parseAuths(strings.NewReader("  extra  spaces  here"))
	if err != nil {
		t.Fatal(err)
	}
	if result["extra"] != "spaces  here" {
		t.Fatalf("expected 'spaces  here', got %q", result["extra"])
	}
}

func TestParseAuths_WhitespaceOnlyLines(t *testing.T) {
	// TrimSpace removes leading/trailing whitespace before SplitN,
	// so whitespace-only lines become empty and produce no entries.
	p := &authenticator{}
	result, err := p.parseAuths(strings.NewReader("   \n\t  "))
	if err != nil || len(result) != 0 {
		t.Fatalf("whitespace-only lines should produce empty map, got %v, %v", result, err)
	}
}

// --- load tests ---

func TestLoad_NoLoaders(t *testing.T) {
	p := &authenticator{logger: xlogger.Nop()}
	m, err := p.load(context.Background())
	if err != nil || len(m) != 0 {
		t.Fatalf("expected empty map, nil err, got %v, %v", m, err)
	}
}

func TestLoad_FileLoaderMapper_Success(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader: &mockMapper{mapData: map[string]string{"a": "b"}},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil || m["a"] != "b" {
		t.Fatalf("expected a=b, got %v, %v", m, err)
	}
}

func TestLoad_FileLoaderMapper_Error(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader: &mockMapper{mapErr: errors.New("map error")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err == nil {
		t.Fatal("expected error from mapper")
	}
}

func TestLoad_FileLoaderNonMapper_Success(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader: &mockLoader{loadData: "u1 p1"},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil || m["u1"] != "p1" {
		t.Fatalf("expected u1=p1, got %v, %v", m, err)
	}
}

func TestLoad_FileLoaderNonMapper_LoadError(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader: &mockLoader{loadErr: errors.New("load error")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err == nil {
		t.Fatal("expected error from loader")
	}
}

func TestLoad_FileLoaderNonMapper_EmptyData(t *testing.T) {
	// mockLoader with empty loadData returns empty string reader;
	// parseAuths succeeds with empty result (not a parse error).
	p := &authenticator{
		options: options{
			fileLoader: &mockLoader{},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil || len(m) != 0 {
		t.Fatalf("expected empty map, got %v, %v", m, err)
	}
}

func TestLoad_RedisLoaderMapper_Success(t *testing.T) {
	p := &authenticator{
		options: options{
			redisLoader: &mockMapper{mapData: map[string]string{"r": "s"}},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil || m["r"] != "s" {
		t.Fatalf("expected r=s, got %v, %v", m, err)
	}
}

func TestLoad_RedisLoaderMapper_Error(t *testing.T) {
	p := &authenticator{
		options: options{
			redisLoader: &mockMapper{mapErr: errors.New("redis error")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err == nil {
		t.Fatal("expected error from redis mapper")
	}
}

func TestLoad_RedisLoaderNonMapper_Success(t *testing.T) {
	p := &authenticator{
		options: options{
			redisLoader: &mockLoader{loadData: "r1 rp1"},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil || m["r1"] != "rp1" {
		t.Fatalf("expected r1=rp1, got %v, %v", m, err)
	}
}

func TestLoad_RedisLoaderNonMapper_LoadError(t *testing.T) {
	p := &authenticator{
		options: options{
			redisLoader: &mockLoader{loadErr: errors.New("redis load err")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoad_RedisLoaderNonMapper_ParseError(t *testing.T) {
	p := &authenticator{
		options: options{
			redisLoader: &mockLoader{loadData: "# comment"},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	// parseAuths succeeds (comments are skipped), just empty
	if err != nil || len(m) != 0 {
		t.Fatalf("expected empty map, got %v, %v", m, err)
	}
}

func TestLoad_HTTPLoader_Success(t *testing.T) {
	p := &authenticator{
		options: options{
			httpLoader: &mockLoader{loadData: "h1 hp1"},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil || m["h1"] != "hp1" {
		t.Fatalf("expected h1=hp1, got %v, %v", m, err)
	}
}

func TestLoad_HTTPLoader_LoadError(t *testing.T) {
	p := &authenticator{
		options: options{
			httpLoader: &mockLoader{loadErr: errors.New("http error")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err == nil {
		t.Fatal("expected error from http loader")
	}
}

func TestLoad_HTTPLoader_ParseError(t *testing.T) {
	p := &authenticator{
		options: options{
			httpLoader: &mockLoader{loadData: "# comment"},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil || len(m) != 0 {
		t.Fatalf("expected empty map, got %v, %v", m, err)
	}
}

func TestLoad_MultipleLoaders_Merge(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader:  &mockLoader{loadData: "f1 fp1"},
			redisLoader: &mockLoader{loadData: "r1 rp1"},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m["f1"] != "fp1" || m["r1"] != "rp1" {
		t.Fatalf("expected merged results, got %v", m)
	}
}

func TestLoad_FirstSuccessSecondError(t *testing.T) {
	// fileLoader succeeds, redisLoader fails — error from redisLoader is returned
	// but fileLoader results are preserved
	p := &authenticator{
		options: options{
			fileLoader:  &mockLoader{loadData: "f1 fp1"},
			redisLoader: &mockLoader{loadErr: errors.New("redis fail")},
		},
		logger: xlogger.Nop(),
	}
	m, err := p.load(context.Background())
	if err == nil {
		t.Fatal("expected error from redis loader")
	}
	if m["f1"] != "fp1" {
		t.Fatalf("file loader results should be preserved, got %v", m)
	}
}

func TestLoad_RedisMapper_ErrorConditionalLoadErr(t *testing.T) {
	// redisLoader mapper error when loadErr is already set (from fileLoader error)
	p := &authenticator{
		options: options{
			fileLoader:  &mockLoader{loadErr: errors.New("file fail")},
			redisLoader: &mockMapper{mapErr: errors.New("redis fail")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	// loadErr was set by fileLoader, redisLoader error doesn't overwrite it
	if err == nil || err.Error() != "file fail" {
		t.Fatalf("expected 'file fail', got %v", err)
	}
}

func TestLoad_HTTPLoader_ErrorConditionalLoadErr(t *testing.T) {
	// httpLoader error when loadErr already set
	p := &authenticator{
		options: options{
			fileLoader: &mockLoader{loadErr: errors.New("file fail")},
			httpLoader: &mockLoader{loadErr: errors.New("http fail")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err == nil || err.Error() != "file fail" {
		t.Fatalf("expected 'file fail' (first error preserved), got %v", err)
	}
}

func TestLoad_FileMapper_ErrorConditionalLoadErr(t *testing.T) {
	// fileLoader mapper error, then redisLoader non-mapper error
	// fileLoader mapper sets loadErr, redisLoader non-mapper doesn't overwrite (conditional)
	p := &authenticator{
		options: options{
			fileLoader:  &mockMapper{mapErr: errors.New("file map fail")},
			redisLoader: &mockLoader{loadErr: errors.New("redis fail")},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err == nil || err.Error() != "file map fail" {
		t.Fatalf("expected 'file map fail', got %v", err)
	}
}

// --- reload tests ---

func TestReload_Success(t *testing.T) {
	p := &authenticator{
		options: options{
			auths: map[string]string{"static": "val"},
		},
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}
	err := p.reload(context.Background())
	if err != nil || len(p.kvs) != 1 || p.kvs["static"] != "val" {
		t.Fatalf("expected static=val, got %v, err=%v", p.kvs, err)
	}
}

func TestReload_LoadError(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader: &mockLoader{loadErr: errors.New("fail")},
		},
		kvs:    map[string]string{"old": "data"},
		logger: xlogger.Nop(),
	}
	err := p.reload(context.Background())
	if err == nil {
		t.Fatal("expected error from reload")
	}
	// On error, kvs should not be updated (old data preserved)
	if p.kvs["old"] != "data" {
		t.Fatal("old kvs should be preserved on reload error")
	}
}

func TestReload_ClearsOldData(t *testing.T) {
	p := &authenticator{
		options: options{
			auths: map[string]string{"new": "val"},
		},
		kvs:    map[string]string{"old": "data"},
		logger: xlogger.Nop(),
	}
	err := p.reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := p.kvs["old"]; exists {
		t.Fatal("old data should be cleared on successful reload")
	}
	if p.kvs["new"] != "val" {
		t.Fatal("new data should be present")
	}
}

// --- periodReload tests ---

func TestPeriodReload_NoPeriod(t *testing.T) {
	p := &authenticator{
		options: options{
			auths: map[string]string{"k": "v"},
		},
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := p.periodReload(ctx)
	if err != nil {
		t.Fatalf("expected nil error for zero period, got %v", err)
	}
	// With period <= 0, the initial reload happened and then returned
	if p.kvs["k"] != "v" {
		t.Fatal("expected k=v after initial reload")
	}
}

func TestPeriodReload_ShortPeriod_Clamped(t *testing.T) {
	p := &authenticator{
		options: options{
			period: 500 * time.Millisecond, // < 1s, gets clamped to 1s
		},
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Initial reload happens, then ticker starts but ctx cancels before first tick
	err := p.periodReload(ctx)
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestPeriodReload_ContextCancellation(t *testing.T) {
	p := &authenticator{
		options: options{
			period: 10 * time.Second, // long period so tick doesn't fire
		},
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- p.periodReload(ctx)
	}()

	// Give it time to complete the initial reload and enter the loop
	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-done
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestPeriodReload_ReloadError_Initial(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader: &mockLoader{loadErr: errors.New("fail")},
			period:     0, // no period, just initial reload
		},
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}
	err := p.periodReload(context.Background())
	// period is 0, so after initial reload it returns nil
	if err != nil {
		t.Fatalf("period 0 should return nil, got %v", err)
	}
}

// --- Close tests ---

func TestClose_NoLoaders(t *testing.T) {
	p := NewAuthenticator()
	err := p.(*authenticator).Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestClose_WithLoaders(t *testing.T) {
	fl := &mockLoader{}
	rl := &mockLoader{}
	hl := &mockLoader{}
	p := NewAuthenticator(
		FileLoaderOption(fl),
		RedisLoaderOption(rl),
		HTTPLoaderOption(hl),
	)
	err := p.(*authenticator).Close()
	if err != nil {
		t.Fatal(err)
	}
	if !fl.closed || !rl.closed || !hl.closed {
		t.Fatal("all loaders should be closed")
	}
}

func TestClose_CallsCancelFunc(t *testing.T) {
	p := &authenticator{
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancelFunc = cancel

	err := p.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Verify context was cancelled
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Fatal("context should be cancelled after Close")
	}
}

// --- AuthenticatorGroup tests ---

func TestAuthenticatorGroup_Empty(t *testing.T) {
	g := AuthenticatorGroup()
	id, ok := g.Authenticate(context.Background(), "u", "p")
	if ok || id != "" {
		t.Fatalf("empty group should return '', false, got %q, %v", id, ok)
	}
}

func TestAuthenticatorGroup_SingleSuccess(t *testing.T) {
	g := AuthenticatorGroup(&staticAuther{id: "user1", ok: true})
	id, ok := g.Authenticate(context.Background(), "u", "p")
	if !ok || id != "user1" {
		t.Fatalf("expected user1, true, got %q, %v", id, ok)
	}
}

func TestAuthenticatorGroup_SingleFail(t *testing.T) {
	g := AuthenticatorGroup(&staticAuther{id: "", ok: false})
	id, ok := g.Authenticate(context.Background(), "u", "p")
	if ok || id != "" {
		t.Fatalf("expected '', false, got %q, %v", id, ok)
	}
}

func TestAuthenticatorGroup_Fallthrough(t *testing.T) {
	g := AuthenticatorGroup(
		&staticAuther{id: "", ok: false},
		&staticAuther{id: "second", ok: true},
	)
	id, ok := g.Authenticate(context.Background(), "u", "p")
	if !ok || id != "second" {
		t.Fatalf("expected second, true, got %q, %v", id, ok)
	}
}

func TestAuthenticatorGroup_NilEntries(t *testing.T) {
	g := AuthenticatorGroup(
		nil,
		&staticAuther{id: "third", ok: true},
	)
	id, ok := g.Authenticate(context.Background(), "u", "p")
	if !ok || id != "third" {
		t.Fatalf("nil entries should be skipped, expected third, true, got %q, %v", id, ok)
	}
}

func TestAuthenticatorGroup_AllFail(t *testing.T) {
	g := AuthenticatorGroup(
		&staticAuther{id: "", ok: false},
		&staticAuther{id: "", ok: false},
	)
	id, ok := g.Authenticate(context.Background(), "u", "p")
	if ok || id != "" {
		t.Fatalf("all fail should return '', false, got %q, %v", id, ok)
	}
}

func TestAuthenticatorGroup_Creation(t *testing.T) {
	a1 := &staticAuther{id: "a", ok: true}
	a2 := &staticAuther{id: "b", ok: false}
	g := AuthenticatorGroup(a1, a2).(*authenticatorGroup)
	if len(g.authers) != 2 {
		t.Fatalf("expected 2 authers, got %d", len(g.authers))
	}
}

// --- scanner error tests ---

type errorReader struct{}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("read error")
}

func TestParseAuths_ScannerError(t *testing.T) {
	p := &authenticator{}
	_, err := p.parseAuths(&errorReader{})
	if err == nil {
		t.Fatal("expected scanner error")
	}
}

// --- load parse error branch tests ---

func TestLoad_FileLoaderNonMapper_ParseErrorBranch(t *testing.T) {
	// File loader non-mapper: Load succeeds but reader triggers scanner error in parseAuths.
	// This hits the "file loader parse" Warnf branch.
	// parse errors are NOT propagated as loadErr — only load errors are.
	p := &authenticator{
		options: options{
			fileLoader: &errorLoader{reader: &errorReader{}},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err != nil {
		t.Fatalf("parse error should not propagate, got %v", err)
	}
}

func TestLoad_RedisLoaderNonMapper_ParseErrorBranch(t *testing.T) {
	// Redis loader non-mapper — parseAuths returns scanner error.
	p := &authenticator{
		options: options{
			redisLoader: &errorLoader{reader: &errorReader{}},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err != nil {
		t.Fatalf("parse error should not propagate, got %v", err)
	}
}

func TestLoad_HTTPLoader_ParseErrorBranch(t *testing.T) {
	// HTTP loader — parseAuths returns scanner error.
	p := &authenticator{
		options: options{
			httpLoader: &errorLoader{reader: &errorReader{}},
		},
		logger: xlogger.Nop(),
	}
	_, err := p.load(context.Background())
	if err != nil {
		t.Fatalf("parse error should not propagate, got %v", err)
	}
}

type errorLoader struct {
	reader io.Reader
}

func (l *errorLoader) Load(ctx context.Context) (io.Reader, error) {
	return l.reader, nil
}

func (l *errorLoader) Close() error { return nil }

var _ loader.Loader = (*errorLoader)(nil)

// --- periodReload ticker fire test ---

func TestPeriodReload_TickerFires(t *testing.T) {
	// Set up with a loader that succeeds on initial reload, so we enter the tick loop.
	// Use period=1s so ticker fires quickly.
	p := &authenticator{
		options: options{
			period:     1 * time.Second,
			fileLoader: &mockLoader{loadData: "k v"},
		},
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- p.periodReload(ctx)
	}()

	err := <-done
	if err == nil {
		t.Fatal("expected context deadline exceeded")
	}

	// kvs should be populated by the initial reload
	p.mu.RLock()
	v := p.kvs["k"]
	p.mu.RUnlock()
	if v != "v" {
		t.Fatalf("expected k=v after initial reload, got %q", v)
	}
}

func TestPeriodReload_TickerReloadError(t *testing.T) {
	// Loader that fails — covers the Warnf inside the ticker.C case.
	// Initial reload fails (Warnf line 116), ticker fires, reload fails again (Warnf line 133).
	p := &authenticator{
		options: options{
			period:     1 * time.Second,
			fileLoader: &mockLoader{loadErr: errors.New("persistent fail")},
		},
		kvs:    make(map[string]string),
		logger: xlogger.Nop(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- p.periodReload(ctx)
	}()

	err := <-done
	if err == nil {
		t.Fatal("expected context deadline exceeded")
	}
}

// --- helper type for group tests ---

type staticAuther struct {
	id string
	ok bool
}

func (s *staticAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	return s.id, s.ok
}

// --- whitelist tests ---

func TestWhitelistedAuthenticator_IPMatch(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: true}, []string{"192.168.1.100"})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "" || !ok {
		t.Fatalf("expected (\"\", true) for matched IP, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_IPNoMatch(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: true}, []string{"192.168.1.100"})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "test" || !ok {
		t.Fatalf("expected (\"test\", true) for non-matched IP, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_CIDRMatch(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: true}, []string{"10.0.0.0/8"})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 9999})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "" || !ok {
		t.Fatalf("expected (\"\", true) for matched CIDR, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_CIDRNoMatch(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: true}, []string{"10.0.0.0/8"})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "test" || !ok {
		t.Fatalf("expected (\"test\", true) for non-matched CIDR, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_EmptyPatterns(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: true}, []string{})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "test" || !ok {
		t.Fatalf("expected (\"test\", true) for empty patterns, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_NoSrcAddr(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: true}, []string{"192.168.1.100"})
	id, ok := w.Authenticate(context.Background(), "user", "pass")
	if id != "test" || !ok {
		t.Fatalf("expected (\"test\", true) with no src addr in context, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_NilAuther(t *testing.T) {
	// When IP matches, the whitelist returns OK regardless of nil auther.
	w := WhitelistedAuthenticator(nil, []string{"192.168.1.100"})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "" || !ok {
		t.Fatalf("expected (\"\", true) for matched whitelist even with nil auther, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_NilAutherNoMatch(t *testing.T) {
	// When IP does not match and auther is nil, it falls through to ("", false).
	w := WhitelistedAuthenticator(nil, []string{"192.168.1.100"})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 54321})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "" || ok {
		t.Fatalf("expected (\"\", false) for nil auther with non-matching IP, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_UnderlyingDenies(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: false}, []string{"10.0.0.0/8"})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "test" || ok {
		t.Fatalf("expected (\"test\", false) when underlying auther denies, got (%q, %v)", id, ok)
	}
}

func TestWhitelistedAuthenticator_InvalidPatterns(t *testing.T) {
	w := WhitelistedAuthenticator(&staticAuther{id: "test", ok: true}, []string{"not-an-ip", "also-not-cidr/", ""})
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321})
	id, ok := w.Authenticate(ctx, "user", "pass")
	if id != "test" || !ok {
		t.Fatalf("expected (\"test\", true) for all-invalid patterns, got (%q, %v)", id, ok)
	}
}
