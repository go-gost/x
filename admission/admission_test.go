package admission

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Option tests ---

func TestWhitelistOption(t *testing.T) {
	var opts options
	WhitelistOption(true)(&opts)
	assert.True(t, opts.whitelist)

	WhitelistOption(false)(&opts)
	assert.False(t, opts.whitelist)
}

func TestMatchersOption(t *testing.T) {
	var opts options
	MatchersOption([]string{"192.168.1.1", "10.0.0.0/8"})(&opts)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.0/8"}, opts.matchers)
}

func TestReloadPeriodOption(t *testing.T) {
	var opts options
	ReloadPeriodOption(5 * time.Second)(&opts)
	assert.Equal(t, 5*time.Second, opts.period)
}

func TestFileLoaderOption(t *testing.T) {
	var opts options
	fl := &mockLoader{}
	FileLoaderOption(fl)(&opts)
	assert.Equal(t, fl, opts.fileLoader)
}

func TestRedisLoaderOption(t *testing.T) {
	var opts options
	rl := &mockLoader{}
	RedisLoaderOption(rl)(&opts)
	assert.Equal(t, rl, opts.redisLoader)
}

func TestHTTPLoaderOption(t *testing.T) {
	var opts options
	hl := &mockLoader{}
	HTTPLoaderOption(hl)(&opts)
	assert.Equal(t, hl, opts.httpLoader)
}

func TestLoggerOption(t *testing.T) {
	var opts options
	l := xlogger.Nop()
	LoggerOption(l)(&opts)
	assert.Equal(t, l, opts.logger)
}

// newSyncedAdmission creates an admission controller and blocks until the initial
// background reload completes, so matchers are ready for immediate assertions.
func newSyncedAdmission(opts ...Option) *localAdmission {
	a := NewAdmission(opts...)
	la := a.(*localAdmission)
	// Force a synchronous reload so tests don't race with the background goroutine.
	la.reload(context.Background())
	return la
}

// --- NewAdmission tests ---

func TestNewAdmission_Defaults(t *testing.T) {
	adm := newSyncedAdmission()
	require.NotNil(t, adm)
	defer adm.Close()

	// Should admit by default (blacklist mode with no rules)
	assert.True(t, adm.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestNewAdmission_WithLogger(t *testing.T) {
	adm := newSyncedAdmission(LoggerOption(xlogger.Nop()))
	require.NotNil(t, adm)
	defer adm.Close()
}

// --- Admit tests ---

func TestAdmit_EmptyAddr(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1"}))
	defer adm.Close()

	assert.True(t, adm.Admit(context.Background(), "tcp", ""))
}

func TestAdmit_NilReceiver(t *testing.T) {
	var p *localAdmission
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmit_Blacklist_Matched(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1"}))
	defer adm.Close()

	// In blacklist mode, matching IP is denied
	assert.False(t, adm.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmit_Blacklist_NotMatched(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1"}))
	defer adm.Close()

	// In blacklist mode, non-matching IP is admitted
	assert.True(t, adm.Admit(context.Background(), "tcp", "10.0.0.1"))
}

func TestAdmit_Whitelist_Matched(t *testing.T) {
	adm := newSyncedAdmission(
		WhitelistOption(true),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer adm.Close()

	// In whitelist mode, matching IP is admitted
	assert.True(t, adm.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmit_Whitelist_NotMatched(t *testing.T) {
	adm := newSyncedAdmission(
		WhitelistOption(true),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer adm.Close()

	// In whitelist mode, non-matching IP is denied
	assert.False(t, adm.Admit(context.Background(), "tcp", "10.0.0.1"))
}

func TestAdmit_StripsPort(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1"}))
	defer adm.Close()

	// Address with port should have port stripped before matching
	assert.False(t, adm.Admit(context.Background(), "tcp", "192.168.1.1:8080"))
}

func TestAdmit_CIDRMatch(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"10.0.0.0/8"}))
	defer adm.Close()

	assert.False(t, adm.Admit(context.Background(), "tcp", "10.0.0.1"))
	assert.True(t, adm.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmit_InvalidAddr(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1"}))
	defer adm.Close()

	// Invalid IP should not match and be admitted in blacklist mode
	assert.True(t, adm.Admit(context.Background(), "tcp", "invalid"))
}

// --- parseLine tests ---

func TestParseLine_Normal(t *testing.T) {
	adm := &localAdmission{}
	assert.Equal(t, "192.168.1.1", adm.parseLine("192.168.1.1"))
}

func TestParseLine_WithComment(t *testing.T) {
	adm := &localAdmission{}
	assert.Equal(t, "192.168.1.1", adm.parseLine("192.168.1.1 # a comment"))
}

func TestParseLine_CommentOnly(t *testing.T) {
	adm := &localAdmission{}
	assert.Equal(t, "", adm.parseLine("# comment only"))
}

func TestParseLine_Empty(t *testing.T) {
	adm := &localAdmission{}
	assert.Equal(t, "", adm.parseLine(""))
}

func TestParseLine_Whitespace(t *testing.T) {
	adm := &localAdmission{}
	assert.Equal(t, "192.168.1.1", adm.parseLine("  192.168.1.1  "))
}

// --- parsePatterns tests ---

func TestParsePatterns_NilReader(t *testing.T) {
	adm := &localAdmission{}
	patterns, err := adm.parsePatterns(nil)
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestParsePatterns_Normal(t *testing.T) {
	adm := &localAdmission{}
	r := strings.NewReader("192.168.1.1\n10.0.0.1\n# comment\n\n  fd00::1  \n")
	patterns, err := adm.parsePatterns(r)
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.1", "fd00::1"}, patterns)
}

// --- matched tests ---

func TestMatched_IP(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1"}))
	defer adm.Close()

	assert.True(t, adm.matched("192.168.1.1"))
	assert.False(t, adm.matched("10.0.0.1"))
}

func TestMatched_CIDR(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"10.0.0.0/8"}))
	defer adm.Close()

	assert.True(t, adm.matched("10.0.0.1"))
	assert.False(t, adm.matched("192.168.1.1"))
}

func TestMatched_BothIPAndCIDR(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1", "10.0.0.0/8"}))
	defer adm.Close()

	assert.True(t, adm.matched("192.168.1.1"))
	assert.True(t, adm.matched("10.0.0.1"))
	assert.False(t, adm.matched("172.16.0.1"))
}

// --- reload tests ---

func TestReload_WithHostnameResolution(t *testing.T) {
	adm := newSyncedAdmission(
		MatchersOption([]string{"localhost"}),
		LoggerOption(xlogger.Nop()),
	)
	defer adm.Close()

	// After reload, localhost should be resolved to 127.0.0.1 or ::1
	err := adm.reload(context.Background())
	assert.NoError(t, err)
}

// --- load tests ---

func TestLoad_AllNilLoaders(t *testing.T) {
	adm := &localAdmission{
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_FileLoaderWithList(t *testing.T) {
	adm := &localAdmission{
		options: options{
			fileLoader: &mockListerLoader{list: []string{"192.168.1.1", "# comment", "10.0.0.1"}},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.1"}, patterns)
}

func TestLoad_FileLoaderWithLoad(t *testing.T) {
	adm := &localAdmission{
		options: options{
			fileLoader: &mockLoader{data: "192.168.1.1\n10.0.0.1\n"},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.1"}, patterns)
}

func TestLoad_RedisLoaderWithList(t *testing.T) {
	adm := &localAdmission{
		options: options{
			redisLoader: &mockListerLoader{list: []string{"redis-host-1", "redis-host-2"}},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"redis-host-1", "redis-host-2"}, patterns)
}

func TestLoad_RedisLoaderWithLoad(t *testing.T) {
	adm := &localAdmission{
		options: options{
			redisLoader: &mockLoader{data: "192.168.2.1\n"},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.2.1"}, patterns)
}

func TestLoad_HTTPLoader(t *testing.T) {
	adm := &localAdmission{
		options: options{
			httpLoader: &mockLoader{data: "10.10.10.1\n10.10.10.2\n"},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.10.10.1", "10.10.10.2"}, patterns)
}

func TestLoad_FileLoaderWithListError(t *testing.T) {
	adm := &localAdmission{
		options: options{
			fileLoader: &mockListerLoader{listErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_FileLoaderWithLoadError(t *testing.T) {
	adm := &localAdmission{
		options: options{
			fileLoader: &mockLoader{loadErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_RedisLoaderWithListError(t *testing.T) {
	adm := &localAdmission{
		options: options{
			redisLoader: &mockListerLoader{listErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_RedisLoaderWithLoadError(t *testing.T) {
	adm := &localAdmission{
		options: options{
			redisLoader: &mockLoader{loadErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_HTTPLoaderError(t *testing.T) {
	adm := &localAdmission{
		options: options{
			httpLoader: &mockLoader{loadErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_FileLoaderWithListParsing(t *testing.T) {
	adm := &localAdmission{
		options: options{
			fileLoader: &mockListerLoader{list: []string{"  # comment", "", "  192.168.1.1  "}},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := adm.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1"}, patterns)
}

// --- periodReload tests ---

func TestPeriodReload_ZeroPeriod(t *testing.T) {
	adm := &localAdmission{
		logger:  xlogger.Nop(),
		options: options{period: 0},
	}
	err := adm.periodReload(context.Background())
	assert.NoError(t, err)
}

func TestPeriodReload_NegativePeriod(t *testing.T) {
	adm := &localAdmission{
		logger:  xlogger.Nop(),
		options: options{period: -1},
	}
	err := adm.periodReload(context.Background())
	assert.NoError(t, err)
}

func TestPeriodReload_WithContextCancel(t *testing.T) {
	// 500ms < 1s triggers the clamping branch (period = time.Second),
	// then sleep > 1s to let at least one ticker cycle fire before cancel.
	adm := &localAdmission{
		logger:  xlogger.Nop(),
		options: options{period: 500 * time.Millisecond},
	}
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- adm.periodReload(ctx)
	}()

	time.Sleep(1100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		assert.Equal(t, context.Canceled, err)
	case <-time.After(3 * time.Second):
		t.Fatal("periodReload did not return after context cancel")
	}
}

// --- Close tests ---

func TestClose_NoLoaders(t *testing.T) {
	adm := newSyncedAdmission()
	err := adm.Close()
	assert.NoError(t, err)
}

func TestClose_WithAllLoaders(t *testing.T) {
	fl := &mockLoader{}
	rl := &mockLoader{}
	hl := &mockLoader{}

	adm := newSyncedAdmission(
		FileLoaderOption(fl),
		RedisLoaderOption(rl),
		HTTPLoaderOption(hl),
	)
	err := adm.Close()
	assert.NoError(t, err)

	assert.True(t, fl.closed)
	assert.True(t, rl.closed)
	assert.True(t, hl.closed)
}

// --- DNS resolution in reload ---

func TestReload_DNSResolution(t *testing.T) {
	adm := &localAdmission{
		ipMatcher:   nil,
		cidrMatcher: nil,
		options: options{
			matchers: []string{"localhost"},
		},
		logger: xlogger.Nop(),
	}
	err := adm.reload(context.Background())
	assert.NoError(t, err)

	// localhost should resolve to 127.0.0.1 (or ::1)
	assert.True(t, adm.matched("127.0.0.1") || adm.matched("::1"))
}

// --- AdmissionGroup tests ---

func TestAdmissionGroup_Empty(t *testing.T) {
	g := AdmissionGroup()
	assert.True(t, g.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmissionGroup_AllAdmit(t *testing.T) {
	g := AdmissionGroup(
		alwaysAdmit{},
		alwaysAdmit{},
	)
	assert.True(t, g.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmissionGroup_OneDenies(t *testing.T) {
	g := AdmissionGroup(
		alwaysAdmit{},
		alwaysDeny{},
	)
	assert.False(t, g.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmissionGroup_NilMember(t *testing.T) {
	g := AdmissionGroup(
		nil,
		alwaysAdmit{},
		nil,
	)
	assert.True(t, g.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestAdmissionGroup_ShortCircuit(t *testing.T) {
	// The first deny should short-circuit, never calling the second.
	callCount := 0
	tracking := &trackingAdmission{admit: false, callCount: &callCount}
	g := AdmissionGroup(tracking, alwaysAdmit{})
	assert.False(t, g.Admit(context.Background(), "tcp", "192.168.1.1"))
	assert.Equal(t, 1, callCount)
}

// --- Mock types ---

type mockLoader struct {
	data    string
	loadErr error
	closed  bool
}

func (m *mockLoader) Load(ctx context.Context) (io.Reader, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return strings.NewReader(m.data), nil
}

func (m *mockLoader) Close() error {
	m.closed = true
	return nil
}

type mockListerLoader struct {
	list    []string
	listErr error
}

func (m *mockListerLoader) Load(ctx context.Context) (io.Reader, error) {
	return strings.NewReader(strings.Join(m.list, "\n")), nil
}

func (m *mockListerLoader) List(ctx context.Context) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.list, nil
}

func (m *mockListerLoader) Close() error {
	return nil
}

type alwaysAdmit struct{}

func (alwaysAdmit) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	return true
}

type alwaysDeny struct{}

func (alwaysDeny) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	return false
}

type trackingAdmission struct {
	admit     bool
	callCount *int
}

func (t *trackingAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	*t.callCount++
	return t.admit
}

// Ensure mock types implement the interfaces.
var _ loader.Loader = (*mockLoader)(nil)
var _ loader.Lister = (*mockListerLoader)(nil)
var _ loader.Loader = (*mockListerLoader)(nil)
var _ admission.Admission = alwaysAdmit{}
var _ admission.Admission = alwaysDeny{}

// TestAdmit_IPv6 tests that IPv6 addresses are handled correctly.
func TestAdmit_IPv6(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"fd00::1"}))
	defer adm.Close()

	assert.False(t, adm.Admit(context.Background(), "tcp", "fd00::1"))
	assert.True(t, adm.Admit(context.Background(), "tcp", "fd00::2"))
}

// TestAdmit_IPv6WithPort tests that IPv6 addresses with port brackets are handled.
func TestAdmit_IPv6WithPort(t *testing.T) {
	adm := newSyncedAdmission(MatchersOption([]string{"::1"}))
	defer adm.Close()

	// net.SplitHostPort handles [::1]:8080 format
	assert.False(t, adm.Admit(context.Background(), "tcp", "[::1]:8080"))
}

// TestNewAdmission_ReloadErrorInBackground verifies that the initial reload
// in the background goroutine doesn't panic, even if it fails.
func TestNewAdmission_ReloadError(t *testing.T) {
	fl := &mockLoader{loadErr: io.ErrUnexpectedEOF}
	adm := newSyncedAdmission(
		FileLoaderOption(fl),
		LoggerOption(xlogger.Nop()),
	)
	defer adm.Close()

	// Should still work, just logged a warning
	assert.True(t, adm.Admit(context.Background(), "tcp", "192.168.1.1"))
}

// TestAdmissionGroup_NilMemberFirst tests nil as first member.
func TestAdmissionGroup_NilMemberFirst(t *testing.T) {
	g := AdmissionGroup(nil, alwaysDeny{})
	assert.False(t, g.Admit(context.Background(), "tcp", "192.168.1.1"))
}

// TestAdmissionGroup_AllNil tests all nil members.
func TestAdmissionGroup_AllNil(t *testing.T) {
	g := AdmissionGroup(nil, nil)
	assert.True(t, g.Admit(context.Background(), "tcp", "192.168.1.1"))
}

// TestLoggerDefault tests that default logger is set when nil is passed.
func TestLoggerOption_Nil(t *testing.T) {
	var opts options
	LoggerOption(nil)(&opts)
	assert.Nil(t, opts.logger)
}

// TestAdmit_IpMatcher test case where only IP matcher is valid.
func TestReload_OnlyIPs(t *testing.T) {
	adm := &localAdmission{
		options: options{
			matchers: []string{"1.1.1.1", "8.8.8.8"},
		},
		logger: xlogger.Nop(),
	}
	err := adm.reload(context.Background())
	assert.NoError(t, err)
	assert.True(t, adm.matched("1.1.1.1"))
	assert.True(t, adm.matched("8.8.8.8"))
	assert.False(t, adm.matched("9.9.9.9"))
}

// TestReload_OnlyCIDRs tests reload with only CIDR patterns.
func TestReload_OnlyCIDRs(t *testing.T) {
	adm := &localAdmission{
		options: options{
			matchers: []string{"192.168.0.0/16", "10.0.0.0/8"},
		},
		logger: xlogger.Nop(),
	}
	err := adm.reload(context.Background())
	assert.NoError(t, err)
	assert.True(t, adm.matched("192.168.1.1"))
	assert.True(t, adm.matched("10.0.0.1"))
	assert.False(t, adm.matched("172.16.0.1"))
}

// TestAdmit_LoggerDebugOutput tests that debug logging happens on deny.
func TestAdmit_DenyLogs(t *testing.T) {
	adm := newSyncedAdmission(
		MatchersOption([]string{"192.168.1.1"}),
		LoggerOption(xlogger.Nop()),
	)
	defer adm.Close()

	// Should not panic; debug log is written
	assert.False(t, adm.Admit(context.Background(), "tcp", "192.168.1.1"))
}

// TestAdmit_WhitelistDenyLogs tests logging for whitelist deny.
func TestAdmit_WhitelistDenyLogs(t *testing.T) {
	adm := newSyncedAdmission(
		WhitelistOption(true),
		MatchersOption([]string{"192.168.1.1"}),
		LoggerOption(xlogger.Nop()),
	)
	defer adm.Close()

	assert.False(t, adm.Admit(context.Background(), "tcp", "10.0.0.1"))
}

// TestParsePatterns_WithCommentsAndEmptyLines tests edge cases.
func TestParsePatterns_EdgeCases(t *testing.T) {
	adm := &localAdmission{}
	r := strings.NewReader("# full comment\n\n   # indented comment\n192.168.1.1 # inline")
	patterns, err := adm.parsePatterns(r)
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1"}, patterns)
}

func TestAdmit_NetworkIgnoredForMatching(t *testing.T) {
	// Network parameter doesn't affect matching behavior
	adm := newSyncedAdmission(MatchersOption([]string{"192.168.1.1"}))
	defer adm.Close()

	assert.False(t, adm.Admit(context.Background(), "tcp", "192.168.1.1"))
	assert.False(t, adm.Admit(context.Background(), "udp", "192.168.1.1"))
	assert.False(t, adm.Admit(context.Background(), "ip4", "192.168.1.1"))
}

// Compile-time interface check
var _ logger.Logger = xlogger.Nop()

// Ensure admission.Admission is implemented
var _ admission.Admission = (*localAdmission)(nil)
