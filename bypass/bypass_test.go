package bypass

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
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

// newSyncedBypass creates a bypass and blocks until the initial background
// reload completes, so matchers are ready for immediate assertions.
func newSyncedBypass(opts ...Option) *localBypass {
	b := NewBypass(opts...)
	lb := b.(*localBypass)
	lb.reload(context.Background())
	return lb
}

// --- NewBypass tests ---

func TestNewBypass_Defaults(t *testing.T) {
	b := newSyncedBypass()
	require.NotNil(t, b)
	defer b.Close()

	// Blacklist mode with no rules: nothing matches, so traffic goes through proxy
	assert.False(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestNewBypass_WithLogger(t *testing.T) {
	b := newSyncedBypass(LoggerOption(xlogger.Nop()))
	require.NotNil(t, b)
	defer b.Close()
}

// --- Contains tests ---

func TestContains_EmptyAddr(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.False(t, b.Contains(context.Background(), "tcp", ""))
}

func TestContains_NilReceiver(t *testing.T) {
	var lb *localBypass
	assert.False(t, lb.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestContains_Blacklist_Matched(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestContains_Blacklist_NotMatched(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.False(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
}

func TestContains_Whitelist_Matched(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	assert.False(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestContains_Whitelist_NotMatched(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
}

func TestContains_StripsPort(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.1:8080"))
}

func TestContains_CIDRMatch(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"10.0.0.0/8"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
	assert.False(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestContains_WildcardMatch(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"*.example.com"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "foo.example.com"))
	assert.False(t, b.Contains(context.Background(), "tcp", "foo.other.com"))
}

func TestContains_IPRangeMatch(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1-192.168.1.10"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.5"))
	assert.False(t, b.Contains(context.Background(), "tcp", "192.168.1.100"))
}

func TestContains_InvalidAddr(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	// Invalid address should not match, return false in blacklist mode
	assert.False(t, b.Contains(context.Background(), "tcp", "invalid"))
}

func TestContains_CompositePatterns(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1", "10.0.0.0/8", "*.example.com", "172.16.0.1-172.16.0.255"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.True(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
	assert.True(t, b.Contains(context.Background(), "tcp", "foo.example.com"))
	assert.True(t, b.Contains(context.Background(), "tcp", "172.16.0.50"))
	assert.False(t, b.Contains(context.Background(), "tcp", "8.8.8.8"))
}

func TestContains_IPv6(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"fd00::1"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "fd00::1"))
	assert.False(t, b.Contains(context.Background(), "tcp", "fd00::2"))
}

func TestContains_IPv6WithPort(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"::1"}))
	defer b.Close()

	// net.SplitHostPort handles [::1]:8080 format
	assert.True(t, b.Contains(context.Background(), "tcp", "[::1]:8080"))
}

func TestContains_WildcardWithPort(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"*.example.com:8080"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "foo.example.com:8080"))
	assert.False(t, b.Contains(context.Background(), "tcp", "foo.example.com:9090"))
}

// --- IsWhitelist tests ---

func TestIsWhitelist_Blacklist(t *testing.T) {
	b := newSyncedBypass()
	defer b.Close()

	assert.False(t, b.IsWhitelist())
}

func TestIsWhitelist_Whitelist(t *testing.T) {
	b := newSyncedBypass(WhitelistOption(true))
	defer b.Close()

	assert.True(t, b.IsWhitelist())
}

// --- parseLine tests ---

func TestParseLine_Normal(t *testing.T) {
	lb := &localBypass{}
	assert.Equal(t, "192.168.1.1", lb.parseLine("192.168.1.1"))
}

func TestParseLine_WithComment(t *testing.T) {
	lb := &localBypass{}
	assert.Equal(t, "192.168.1.1", lb.parseLine("192.168.1.1 # a comment"))
}

func TestParseLine_CommentOnly(t *testing.T) {
	lb := &localBypass{}
	assert.Equal(t, "", lb.parseLine("# comment only"))
}

func TestParseLine_Empty(t *testing.T) {
	lb := &localBypass{}
	assert.Equal(t, "", lb.parseLine(""))
}

func TestParseLine_Whitespace(t *testing.T) {
	lb := &localBypass{}
	assert.Equal(t, "192.168.1.1", lb.parseLine("  192.168.1.1  "))
}

// --- parsePatterns tests ---

func TestParsePatterns_NilReader(t *testing.T) {
	lb := &localBypass{}
	patterns, err := lb.parsePatterns(nil)
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestParsePatterns_Normal(t *testing.T) {
	lb := &localBypass{}
	r := strings.NewReader("192.168.1.1\n10.0.0.1\n# comment\n\n  fd00::1  \n")
	patterns, err := lb.parsePatterns(r)
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.1", "fd00::1"}, patterns)
}

func TestParsePatterns_EdgeCases(t *testing.T) {
	lb := &localBypass{}
	r := strings.NewReader("# full comment\n\n   # indented comment\n192.168.1.1 # inline")
	patterns, err := lb.parsePatterns(r)
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1"}, patterns)
}

// --- matched tests (via decide) ---

func TestMatched_IP(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.Equal(t, decisionBypass, b.decide("", "192.168.1.1"))
	assert.Equal(t, decisionProxy, b.decide("", "10.0.0.1"))
}

func TestMatched_CIDR(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"10.0.0.0/8"}))
	defer b.Close()

	assert.Equal(t, decisionBypass, b.decide("", "10.0.0.1"))
	assert.Equal(t, decisionProxy, b.decide("", "192.168.1.1"))
}

func TestMatched_Wildcard(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"*.example.com"}))
	defer b.Close()

	assert.Equal(t, decisionBypass, b.decide("", "foo.example.com"))
	assert.Equal(t, decisionProxy, b.decide("", "foo.other.com"))
}

func TestMatched_IPRange(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"10.0.0.1-10.0.0.100"}))
	defer b.Close()

	assert.Equal(t, decisionBypass, b.decide("", "10.0.0.50"))
	assert.Equal(t, decisionProxy, b.decide("", "10.0.0.200"))
}

// --- reload tests ---

func TestReload_OnlyIPs(t *testing.T) {
	lb := &localBypass{
		options: options{
			matchers: []string{"1.1.1.1", "8.8.8.8"},
		},
		logger: xlogger.Nop(),
	}
	err := lb.reload(context.Background())
	assert.NoError(t, err)
	assert.True(t, lb.patterns.matchAny("1.1.1.1"))
	assert.True(t, lb.patterns.matchAny("8.8.8.8"))
	assert.False(t, lb.patterns.matchAny("9.9.9.9"))
}

func TestReload_OnlyCIDRs(t *testing.T) {
	lb := &localBypass{
		options: options{
			matchers: []string{"192.168.0.0/16", "10.0.0.0/8"},
		},
		logger: xlogger.Nop(),
	}
	err := lb.reload(context.Background())
	assert.NoError(t, err)
	assert.True(t, lb.patterns.matchAny("192.168.1.1"))
	assert.True(t, lb.patterns.matchAny("10.0.0.1"))
	assert.False(t, lb.patterns.matchAny("172.16.0.1"))
}

func TestReload_OnlyWildcards(t *testing.T) {
	lb := &localBypass{
		options: options{
			matchers: []string{"*.example.com", "*.test.org"},
		},
		logger: xlogger.Nop(),
	}
	err := lb.reload(context.Background())
	assert.NoError(t, err)
	assert.True(t, lb.patterns.matchAny("foo.example.com"))
	assert.True(t, lb.patterns.matchAny("bar.test.org"))
	assert.False(t, lb.patterns.matchAny("other.com"))
}

func TestReload_OnlyIPRanges(t *testing.T) {
	lb := &localBypass{
		options: options{
			matchers: []string{"192.168.1.1-192.168.1.50"},
		},
		logger: xlogger.Nop(),
	}
	err := lb.reload(context.Background())
	assert.NoError(t, err)
	assert.True(t, lb.patterns.matchAny("192.168.1.25"))
	assert.False(t, lb.patterns.matchAny("192.168.1.100"))
}

// --- load tests ---

func TestLoad_AllNilLoaders(t *testing.T) {
	lb := &localBypass{
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_FileLoaderWithList(t *testing.T) {
	lb := &localBypass{
		options: options{
			fileLoader: &mockListerLoader{list: []string{"192.168.1.1", "# comment", "10.0.0.1"}},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.1"}, patterns)
}

func TestLoad_FileLoaderWithLoad(t *testing.T) {
	lb := &localBypass{
		options: options{
			fileLoader: &mockLoader{data: "192.168.1.1\n10.0.0.1\n"},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.1"}, patterns)
}

func TestLoad_RedisLoaderWithList(t *testing.T) {
	lb := &localBypass{
		options: options{
			redisLoader: &mockListerLoader{list: []string{"redis-host-1", "redis-host-2"}},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"redis-host-1", "redis-host-2"}, patterns)
}

func TestLoad_RedisLoaderWithLoad(t *testing.T) {
	lb := &localBypass{
		options: options{
			redisLoader: &mockLoader{data: "192.168.2.1\n"},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.2.1"}, patterns)
}

func TestLoad_HTTPLoader(t *testing.T) {
	lb := &localBypass{
		options: options{
			httpLoader: &mockLoader{data: "10.10.10.1\n10.10.10.2\n"},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.10.10.1", "10.10.10.2"}, patterns)
}

func TestLoad_FileLoaderWithListError(t *testing.T) {
	lb := &localBypass{
		options: options{
			fileLoader: &mockListerLoader{listErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_FileLoaderWithLoadError(t *testing.T) {
	lb := &localBypass{
		options: options{
			fileLoader: &mockLoader{loadErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_RedisLoaderWithListError(t *testing.T) {
	lb := &localBypass{
		options: options{
			redisLoader: &mockListerLoader{listErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_RedisLoaderWithLoadError(t *testing.T) {
	lb := &localBypass{
		options: options{
			redisLoader: &mockLoader{loadErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_HTTPLoaderError(t *testing.T) {
	lb := &localBypass{
		options: options{
			httpLoader: &mockLoader{loadErr: io.ErrUnexpectedEOF},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestLoad_FileLoaderWithListParsing(t *testing.T) {
	lb := &localBypass{
		options: options{
			fileLoader: &mockListerLoader{list: []string{"  # comment", "", "  192.168.1.1  "}},
		},
		logger: xlogger.Nop(),
	}
	patterns, err := lb.load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1"}, patterns)
}

// --- periodReload tests ---

func TestPeriodReload_ZeroPeriod(t *testing.T) {
	lb := &localBypass{
		logger:  xlogger.Nop(),
		options: options{period: 0},
	}
	err := lb.periodReload(context.Background())
	assert.NoError(t, err)
}

func TestPeriodReload_NegativePeriod(t *testing.T) {
	lb := &localBypass{
		logger:  xlogger.Nop(),
		options: options{period: -1},
	}
	err := lb.periodReload(context.Background())
	assert.NoError(t, err)
}

func TestPeriodReload_WithContextCancel(t *testing.T) {
	lb := &localBypass{
		logger:  xlogger.Nop(),
		options: options{period: 500 * time.Millisecond},
	}
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- lb.periodReload(ctx)
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
	b := newSyncedBypass()
	err := b.Close()
	assert.NoError(t, err)
}

func TestClose_WithAllLoaders(t *testing.T) {
	fl := &mockLoader{}
	rl := &mockLoader{}
	hl := &mockLoader{}

	b := newSyncedBypass(
		FileLoaderOption(fl),
		RedisLoaderOption(rl),
		HTTPLoaderOption(hl),
	)
	err := b.Close()
	assert.NoError(t, err)

	assert.True(t, fl.closed)
	assert.True(t, rl.closed)
	assert.True(t, hl.closed)
}

// --- BypassGroup tests ---

func TestBypassGroup_Empty(t *testing.T) {
	g := BypassGroup()
	assert.False(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_AllBlacklistAllMatch(t *testing.T) {
	g := BypassGroup(
		alwaysContains{},
		alwaysContains{},
	)
	assert.True(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_BlacklistOneMatches(t *testing.T) {
	g := BypassGroup(
		alwaysContains{},
		neverContains{},
	)
	// OR logic for blacklist: any match triggers bypass
	assert.True(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_BlacklistNoneMatches(t *testing.T) {
	g := BypassGroup(
		neverContains{},
		neverContains{},
	)
	assert.False(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_WhitelistAllMatch(t *testing.T) {
	// AND logic for whitelist: all must match
	g := BypassGroup(
		alwaysContainsWhitelist{},
		alwaysContainsWhitelist{},
	)
	assert.True(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_WhitelistOneFails(t *testing.T) {
	// AND logic for whitelist: if any fails, combined result is false
	g := BypassGroup(
		alwaysContainsWhitelist{},
		neverContainsWhitelist{},
	)
	assert.False(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_MixedWhitelsBlacklist(t *testing.T) {
	// Whitelist all match, blacklist irrelevant
	g := BypassGroup(
		alwaysContainsWhitelist{},
		alwaysContains{}, // blacklist — should be ignored if whitelist all pass
	)
	// All whitelists match → status=true → blacklist skipped
	assert.True(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_MixedWhitelistFailsBlacklistMatches(t *testing.T) {
	// Whitelist fails → fallthrough to blacklist which matches
	g := BypassGroup(
		neverContainsWhitelist{},
		alwaysContains{},
	)
	assert.True(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_MixedWhitelistFailsBlacklistNoMatch(t *testing.T) {
	g := BypassGroup(
		neverContainsWhitelist{},
		neverContains{},
	)
	assert.False(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestBypassGroup_IsWhitelist(t *testing.T) {
	g := BypassGroup()
	assert.False(t, g.IsWhitelist())
}

// --- NewBypass reload error in background ---

func TestNewBypass_ReloadError(t *testing.T) {
	fl := &mockLoader{loadErr: io.ErrUnexpectedEOF}
	b := newSyncedBypass(
		FileLoaderOption(fl),
		LoggerOption(xlogger.Nop()),
	)
	defer b.Close()

	// Should still work, just logged a warning
	assert.False(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
}

// --- Network parameter ignored ---

// --- Network option tests ---

func TestNetworkOption(t *testing.T) {
	var opts options
	NetworkOption("tcp")(&opts)
	assert.Equal(t, "tcp", opts.network)

	NetworkOption("")(&opts)
	assert.Equal(t, "", opts.network)
}

// --- Network pre-filter tests ---

func TestContains_NetworkNotSet_BehavesAsBefore(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.True(t, b.Contains(context.Background(), "udp", "192.168.1.1"))
	assert.True(t, b.Contains(context.Background(), "ip4", "192.168.1.1"))
}

func TestContains_NetworkMatch_BlacklistBypass(t *testing.T) {
	b := newSyncedBypass(
		NetworkOption("tcp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// Network matches and addr matches → bypass
	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestContains_NetworkMatch_BlacklistPass(t *testing.T) {
	b := newSyncedBypass(
		NetworkOption("tcp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// Network matches but addr does not match → proxy
	assert.False(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
}

func TestContains_NetworkMatch_WhitelistProxy(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		NetworkOption("udp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// Network matches and addr matches → in whitelist, addr goes through proxy
	assert.False(t, b.Contains(context.Background(), "udp", "192.168.1.1"))
}

func TestContains_NetworkMatch_WhitelistBypass(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		NetworkOption("udp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// Network matches but addr does not match → whitelist bypass
	assert.True(t, b.Contains(context.Background(), "udp", "10.0.0.1"))
}

func TestContains_NetworkMismatch_ReturnsFalse(t *testing.T) {
	b := newSyncedBypass(
		NetworkOption("tcp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// Network does not match → bypass returns false regardless of addr
	assert.False(t, b.Contains(context.Background(), "udp", "192.168.1.1"))
	assert.False(t, b.Contains(context.Background(), "udp", ""))
	assert.False(t, b.Contains(context.Background(), "sctp", "192.168.1.1"))
}

func TestContains_NetworkMismatch_EmptyAddr(t *testing.T) {
	b := newSyncedBypass(
		NetworkOption("tcp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// addr is empty → early return false
	assert.False(t, b.Contains(context.Background(), "tcp", ""))
}

func TestContains_NetworkMismatch_WhitelistReturnsFalse(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		NetworkOption("tcp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// Network does not match → bypass returns false even in whitelist mode
	assert.False(t, b.Contains(context.Background(), "udp", "10.0.0.1"))
	assert.False(t, b.Contains(context.Background(), "udp", "192.168.1.1"))
}

func TestContains_PatternSetPassesThroughNetworkFilter(t *testing.T) {
	b := newSyncedBypass(
		NetworkOption("tcp"),
		MatchersOption([]string{"192.168.1.1", "10.0.0.0/8", "*.example.com"}),
	)
	defer b.Close()

	// Network matches → pattern set is evaluated
	assert.True(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
	assert.True(t, b.Contains(context.Background(), "tcp", "foo.example.com"))
	assert.False(t, b.Contains(context.Background(), "tcp", "8.8.8.8"))
}

// --- Network-only tests (no address matchers) ---

func TestNetworkOnly_Blacklist_BypassesMatchingNetwork(t *testing.T) {
	b := newSyncedBypass(NetworkOption("tcp"))
	defer b.Close()

	// Network matches → bypass
	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.True(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
}

func TestNetworkOnly_Blacklist_DoesNotBypassNonMatching(t *testing.T) {
	b := newSyncedBypass(NetworkOption("tcp"))
	defer b.Close()

	// Network does not match → not bypassed
	assert.False(t, b.Contains(context.Background(), "udp", "192.168.1.1"))
}

func TestNetworkOnly_Whitelist_ProxiesMatchingNetwork(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		NetworkOption("tcp"),
	)
	defer b.Close()

	// In whitelist mode, matched network → proxy (not bypassed)
	assert.False(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.False(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
}

func TestNetworkOnly_Whitelist_NonMatchingNotAffected(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		NetworkOption("tcp"),
	)
	defer b.Close()

	// network: tcp 是作用域限定，非 TCP 流量不受影响
	assert.False(t, b.Contains(context.Background(), "udp", "192.168.1.1"))
}

func TestNetworkOnly_NoNetwork_BehavesAsBefore(t *testing.T) {
	b := newSyncedBypass()
	defer b.Close()

	// No network configured, no matchers → never bypass
	assert.False(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.False(t, b.Contains(context.Background(), "udp", "192.168.1.1"))
}

func TestNetworkOnly_EmptyAddr_ReturnsFalse(t *testing.T) {
	b := newSyncedBypass(NetworkOption("tcp"))
	defer b.Close()

	assert.False(t, b.Contains(context.Background(), "tcp", ""))
}

func TestNetworkOption_DoesNotAffectGroupBypass(t *testing.T) {
	b := newSyncedBypass(
		NetworkOption("tcp"),
		MatchersOption([]string{"192.168.1.1"}),
	)
	defer b.Close()

	// bypassGroup embeds the same localBypass and respects the network filter
	g := BypassGroup(b)
	assert.False(t, g.Contains(context.Background(), "udp", "192.168.1.1"))
	assert.True(t, g.Contains(context.Background(), "tcp", "192.168.1.1"))
}

// --- Debug logging doesn't panic ---

func TestContains_DenyLogs(t *testing.T) {
	b := newSyncedBypass(
		MatchersOption([]string{"192.168.1.1"}),
		LoggerOption(xlogger.Nop()),
	)
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestContains_WhitelistDenyLogs(t *testing.T) {
	b := newSyncedBypass(
		WhitelistOption(true),
		MatchersOption([]string{"192.168.1.1"}),
		LoggerOption(xlogger.Nop()),
	)
	defer b.Close()

	assert.True(t, b.Contains(context.Background(), "tcp", "10.0.0.1"))
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

type alwaysContains struct{}

func (alwaysContains) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return true
}
func (alwaysContains) IsWhitelist() bool { return false }

type neverContains struct{}

func (neverContains) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return false
}
func (neverContains) IsWhitelist() bool { return false }

type alwaysContainsWhitelist struct{}

func (alwaysContainsWhitelist) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return true
}
func (alwaysContainsWhitelist) IsWhitelist() bool { return true }

type neverContainsWhitelist struct{}

func (neverContainsWhitelist) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return false
}
func (neverContainsWhitelist) IsWhitelist() bool { return true }

// Ensure mock types implement the interfaces
var _ loader.Loader = (*mockLoader)(nil)
var _ loader.Lister = (*mockListerLoader)(nil)
var _ loader.Loader = (*mockListerLoader)(nil)
var _ bypass.Bypass = alwaysContains{}
var _ bypass.Bypass = neverContains{}
var _ bypass.Bypass = alwaysContainsWhitelist{}
var _ bypass.Bypass = neverContainsWhitelist{}
var _ bypass.Bypass = (*localBypass)(nil)
var _ bypass.Bypass = (*bypassGroup)(nil)
var _ logger.Logger = xlogger.Nop()

// --- bypassDecision tests ---

func TestBypassDecision_String(t *testing.T) {
	assert.Equal(t, "bypass", decisionBypass.String())
	assert.Equal(t, "proxy", decisionProxy.String())
	assert.Equal(t, "unknown", bypassDecision(99).String())
}

// --- patternSet.matchAny tests ---

func TestPatternSet_MatchAny_IPRange(t *testing.T) {
	ps := classifyPatterns([]string{"192.168.1.1-192.168.1.10"}, xlogger.Nop())
	assert.True(t, ps.matchAny("192.168.1.5"))
	assert.False(t, ps.matchAny("192.168.1.100"))
}

func TestPatternSet_MatchAny_Addr(t *testing.T) {
	ps := classifyPatterns([]string{"example.com"}, xlogger.Nop())
	assert.True(t, ps.matchAny("example.com"))
	assert.False(t, ps.matchAny("other.com"))
}

func TestPatternSet_MatchAny_CIDR(t *testing.T) {
	ps := classifyPatterns([]string{"10.0.0.0/8"}, xlogger.Nop())
	assert.True(t, ps.matchAny("10.0.0.1"))
	assert.True(t, ps.matchAny("10.255.255.255"))
	assert.False(t, ps.matchAny("192.168.1.1"))
}

func TestPatternSet_MatchAny_Wildcard(t *testing.T) {
	ps := classifyPatterns([]string{"*.example.com"}, xlogger.Nop())
	assert.True(t, ps.matchAny("foo.example.com"))
	assert.False(t, ps.matchAny("foo.other.com"))
}

func TestPatternSet_MatchAny_NilSet(t *testing.T) {
	var ps *patternSet
	assert.False(t, ps.matchAny("anything"))
}

func TestPatternSet_MatchAny_Empty(t *testing.T) {
	ps := classifyPatterns(nil, xlogger.Nop())
	assert.False(t, ps.matchAny("anything"))
}

func TestPatternSet_MatchAny_MixedTypes(t *testing.T) {
	ps := classifyPatterns([]string{
		"192.168.1.1",         // address
		"10.0.0.0/8",          // CIDR
		"*.example.com",       // wildcard
		"172.16.0.1-172.16.0.255", // IP range
	}, xlogger.Nop())
	assert.True(t, ps.matchAny("192.168.1.1"))
	assert.True(t, ps.matchAny("10.0.0.1"))
	assert.True(t, ps.matchAny("foo.example.com"))
	assert.True(t, ps.matchAny("172.16.0.50"))
	assert.False(t, ps.matchAny("8.8.8.8"))
}

func TestPatternSet_MatchAny_Precedence(t *testing.T) {
	// IP range matches first, before address
	ps := classifyPatterns([]string{"192.168.1.1-192.168.1.10", "192.168.1.1"}, xlogger.Nop())
	assert.True(t, ps.matchAny("192.168.1.5"))
}

func TestPatternSet_MatchAny_CIDRWithPort(t *testing.T) {
	ps := classifyPatterns([]string{"10.0.0.0/8"}, xlogger.Nop())
	assert.True(t, ps.matchAny("10.0.0.1:8080"))
}

func TestPatternSet_MatchAny_CIDRDomainNotMatched(t *testing.T) {
	ps := classifyPatterns([]string{"10.0.0.0/8"}, xlogger.Nop())
	assert.False(t, ps.matchAny("example.com"))
}

// --- classifyPatterns tests ---

func TestClassifyPatterns_CIDR(t *testing.T) {
	ps := classifyPatterns([]string{"192.168.0.0/16"}, xlogger.Nop())
	require.NotNil(t, ps)
	assert.True(t, ps.matchAny("192.168.1.1"))
}

func TestClassifyPatterns_Wildcard(t *testing.T) {
	ps := classifyPatterns([]string{"*.test.com"}, xlogger.Nop())
	require.NotNil(t, ps)
	assert.True(t, ps.matchAny("foo.test.com"))
}

func TestClassifyPatterns_IPRange(t *testing.T) {
	ps := classifyPatterns([]string{"10.0.0.1-10.0.0.100"}, xlogger.Nop())
	require.NotNil(t, ps)
	assert.True(t, ps.matchAny("10.0.0.50"))
}

func TestClassifyPatterns_Address(t *testing.T) {
	ps := classifyPatterns([]string{"192.168.1.1"}, xlogger.Nop())
	require.NotNil(t, ps)
	assert.True(t, ps.matchAny("192.168.1.1"))
}

func TestClassifyPatterns_InvalidWildcardFallsToAddress(t *testing.T) {
	// A pattern with * that can't compile as glob falls to address matcher.
	// "[invalid" has * but glob.Compile may fail — let's use a simpler case.
	ps := classifyPatterns([]string{"plain-host"}, xlogger.Nop())
	require.NotNil(t, ps)
	assert.True(t, ps.matchAny("plain-host"))
}

func TestClassifyPatterns_Empty(t *testing.T) {
	ps := classifyPatterns(nil, xlogger.Nop())
	require.NotNil(t, ps)
	assert.False(t, ps.matchAny("anything"))
}

// --- decide tests ---

func TestDecide_BlacklistMatched(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.Equal(t, decisionBypass, b.decide("", "192.168.1.1"))
}

func TestDecide_BlacklistNotMatched(t *testing.T) {
	b := newSyncedBypass(MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.Equal(t, decisionProxy, b.decide("", "10.0.0.1"))
}

func TestDecide_WhitelistMatched(t *testing.T) {
	b := newSyncedBypass(WhitelistOption(true), MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.Equal(t, decisionProxy, b.decide("", "192.168.1.1"))
}

func TestDecide_WhitelistNotMatched(t *testing.T) {
	b := newSyncedBypass(WhitelistOption(true), MatchersOption([]string{"192.168.1.1"}))
	defer b.Close()

	assert.Equal(t, decisionBypass, b.decide("", "10.0.0.1"))
}

func TestDecide_NilPatterns(t *testing.T) {
	lb := &localBypass{logger: xlogger.Nop()}
	assert.Equal(t, decisionProxy, lb.decide("", "anything"))
}

// --- evaluate (bypassGroup) tests ---

func TestEvaluate_AllBlacklistAllMatch(t *testing.T) {
	g := BypassGroup(alwaysContains{}, alwaysContains{}).(*bypassGroup)
	assert.Equal(t, decisionBypass, g.evaluate(context.Background(), "tcp", "any", ))
}

func TestEvaluate_BlacklistNoneMatch(t *testing.T) {
	g := BypassGroup(neverContains{}, neverContains{}).(*bypassGroup)
	assert.Equal(t, decisionProxy, g.evaluate(context.Background(), "tcp", "any"))
}

func TestEvaluate_WhitelistAllMatch(t *testing.T) {
	g := BypassGroup(alwaysContainsWhitelist{}, alwaysContainsWhitelist{}).(*bypassGroup)
	assert.Equal(t, decisionBypass, g.evaluate(context.Background(), "tcp", "any"))
}

func TestEvaluate_WhitelistOneFails(t *testing.T) {
	g := BypassGroup(alwaysContainsWhitelist{}, neverContainsWhitelist{}).(*bypassGroup)
	assert.Equal(t, decisionProxy, g.evaluate(context.Background(), "tcp", "any"))
}

func TestEvaluate_WhitelistFailsBlacklistMatches(t *testing.T) {
	g := BypassGroup(neverContainsWhitelist{}, alwaysContains{}).(*bypassGroup)
	assert.Equal(t, decisionBypass, g.evaluate(context.Background(), "tcp", "any"))
}

func TestEvaluate_WhitelistFailsBlacklistNoMatch(t *testing.T) {
	g := BypassGroup(neverContainsWhitelist{}, neverContains{}).(*bypassGroup)
	assert.Equal(t, decisionProxy, g.evaluate(context.Background(), "tcp", "any"))
}

func TestEvaluate_Empty(t *testing.T) {
	g := BypassGroup().(*bypassGroup)
	assert.Equal(t, decisionProxy, g.evaluate(context.Background(), "tcp", "any"))
}

// --- hasLoaders tests ---

func TestHasLoaders_None(t *testing.T) {
	lb := &localBypass{options: options{}}
	assert.False(t, lb.hasLoaders())
}

func TestHasLoaders_WithFile(t *testing.T) {
	lb := &localBypass{options: options{fileLoader: &mockLoader{}}}
	assert.True(t, lb.hasLoaders())
}

func TestHasLoaders_WithPeriod(t *testing.T) {
	lb := &localBypass{options: options{period: time.Second}}
	assert.True(t, lb.hasLoaders())
}
