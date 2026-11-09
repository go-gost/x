package resolver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
	"github.com/miekg/dns"
)

func TestCacheStatsCountsHitsMissesStores(t *testing.T) {
	c := NewCache().WithLogger(xlogger.Nop())
	q := dns.Question{Name: "example.com.", Qclass: dns.ClassINET, Qtype: dns.TypeA}
	key := NewCacheKey(&q)

	// First load is a miss.
	_, _ = c.Load(context.Background(), key)
	st := c.Stats()
	if st.Misses != 1 || st.Hits != 0 || st.Stores != 0 {
		t.Fatalf("after miss = %+v", st)
	}

	// Store a response.
	msg := &dns.Msg{}
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Ttl: 60},
		A:   net.ParseIP("127.0.0.1"),
	})
	c.Store(context.Background(), key, msg, time.Minute)
	st = c.Stats()
	if st.Misses != 1 || st.Hits != 0 || st.Stores != 1 {
		t.Fatalf("after store = %+v", st)
	}

	// Second load is a hit.
	_, _ = c.Load(context.Background(), key)
	st = c.Stats()
	if st.Misses != 1 || st.Hits != 1 || st.Stores != 1 {
		t.Fatalf("after hit = %+v", st)
	}

	// Expired entries still count as hits.
	c.entries[key] = &cacheItem{msg: msg.Copy(), ts: time.Now().Add(-time.Hour), ttl: time.Minute}
	_, _ = c.Load(context.Background(), key)
	st = c.Stats()
	if st.Misses != 1 || st.Hits != 2 || st.Stores != 1 {
		t.Fatalf("after expired hit = %+v", st)
	}
}

func TestCacheStatsConcurrent(t *testing.T) {
	c := NewCache().WithLogger(xlogger.Nop())
	q := dns.Question{Name: "example.com.", Qclass: dns.ClassINET, Qtype: dns.TypeA}
	key := NewCacheKey(&q)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = c.Load(context.Background(), key)
				c.Store(context.Background(), key, &dns.Msg{}, time.Minute)
			}
		}()
	}
	wg.Wait()
	_ = c.Stats()
}
