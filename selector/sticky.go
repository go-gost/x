package selector

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"

	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/selector"
	xctx "github.com/go-gost/x/ctx"
	mdutil "github.com/go-gost/x/metadata/util"
)

// StickyHashStrategy selects a node by weighted rendezvous hashing.
//
// A client (for example a conversation identified by its session header)
// always selects the same node while the eligible set and the weights are
// unchanged, so the upstream's prompt cache stays warm. When a node is
// removed from the eligible set, only the clients that hashed to it move;
// the others keep their node. The strategy is stateless: the mapping survives
// restarts and reloads as long as the node keys and weights do not change.
//
// key returns the stable identity of a node. Clients without a client ID fall
// back to weighted random selection.
func StickyHashStrategy[T any](key func(T) string) selector.Strategy[T] {
	return &stickyHashStrategy[T]{key: key}
}

type stickyHashStrategy[T any] struct {
	key func(T) string
}

func (s *stickyHashStrategy[T]) Apply(ctx context.Context, vs ...T) (v T) {
	if len(vs) == 0 {
		return
	}
	if len(vs) == 1 {
		return vs[0]
	}

	clientID := strings.TrimSpace(string(xctx.ClientIDFromContext(ctx)))
	if clientID == "" || s.key == nil {
		return weightedRandom(vs...)
	}

	best := math.Inf(1)
	for i := range vs {
		weight := nodeWeight(vs[i])

		// SHA-256 decorrelates similar node names. A weak hash (FNV-1a)
		// skewed the 10:3 split to about 0.89 for r/oc/oc and r/cc/cc.
		sum := sha256.Sum256([]byte(clientID + "\x00" + s.key(vs[i])))
		h := binary.BigEndian.Uint64(sum[:8])

		// Map the top 53 bits to u in (0,1), then use the weighted
		// rendezvous score -ln(u)/weight. The node with the smallest
		// score wins with probability weight/sum(weights).
		u := (float64(h>>11) + 1) / (1<<53 + 1)
		score := -math.Log(u) / float64(weight)
		if score < best {
			best = score
			v = vs[i]
		}
	}
	return v
}

// weightedRandom selects an item with probability proportional to its
// metadata weight. Items without a positive weight count as 1.
func weightedRandom[T any](vs ...T) (v T) {
	if len(vs) == 0 {
		return
	}
	rw := NewRandomWeighted[T]()
	for i := range vs {
		rw.Add(vs[i], nodeWeight(vs[i]))
	}
	return rw.Next()
}

// nodeWeight returns the metadata weight of v, defaulting to 1.
func nodeWeight[T any](v T) int {
	weight := 0
	if md, _ := any(v).(metadata.Metadatable); md != nil {
		weight = mdutil.GetInt(md.Metadata(), labelWeight)
	}
	if weight <= 0 {
		weight = 1
	}
	return weight
}
