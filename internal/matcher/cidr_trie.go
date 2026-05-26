package matcher

import (
	"net"
	"net/netip"
)

// cidrTrie is a binary trie for zero-allocation netip.Prefix containment lookups.
// IPv4 and IPv6 prefixes are stored in separate sub-tries.
type cidrTrie struct {
	root4 *cidrNode
	root6 *cidrNode
}

type cidrNode struct {
	hasEntry bool
	children [2]*cidrNode
}

func newCIDRTrie() *cidrTrie {
	return &cidrTrie{}
}

// insert adds prefix to the trie.
func (t *cidrTrie) insert(prefix netip.Prefix) {
	addr := prefix.Addr()
	bits := prefix.Bits()
	if bits == 0 {
		// Match everything for this address family.
		root := t.root(addr)
		if root == nil {
			root = &cidrNode{hasEntry: true}
			t.setRoot(addr, root)
		} else {
			root.hasEntry = true
		}
		return
	}

	root := t.rootOrCreate(addr)
	b := addr.As16()
	maxBits := 128
	if addr.Is4() || addr.Is4In6() {
		maxBits = 32
	}
	if bits > maxBits {
		bits = maxBits
	}

	node := root
	for i := 0; i < bits; i++ {
		bit := bitAt(b, i, addr.Is4() || addr.Is4In6())
		if node.children[bit] == nil {
			node.children[bit] = &cidrNode{}
		}
		node = node.children[bit]
	}
	node.hasEntry = true
}

// contains reports whether any inserted prefix covers addr.
func (t *cidrTrie) contains(addr netip.Addr) bool {
	root := t.root(addr)
	if root == nil {
		return false
	}
	if root.hasEntry {
		return true
	}

	b := addr.As16()
	is4 := addr.Is4() || addr.Is4In6()
	maxBits := 128
	if is4 {
		maxBits = 32
	}

	node := root
	for i := 0; i < maxBits; i++ {
		bit := bitAt(b, i, is4)
		child := node.children[bit]
		if child == nil {
			return false
		}
		if child.hasEntry {
			return true
		}
		node = child
	}
	return false
}

func (t *cidrTrie) root(addr netip.Addr) *cidrNode {
	if addr.Is4() || addr.Is4In6() {
		return t.root4
	}
	return t.root6
}

func (t *cidrTrie) setRoot(addr netip.Addr, n *cidrNode) {
	if addr.Is4() || addr.Is4In6() {
		t.root4 = n
	} else {
		t.root6 = n
	}
}

func (t *cidrTrie) rootOrCreate(addr netip.Addr) *cidrNode {
	if addr.Is4() || addr.Is4In6() {
		if t.root4 == nil {
			t.root4 = &cidrNode{}
		}
		return t.root4
	}
	if t.root6 == nil {
		t.root6 = &cidrNode{}
	}
	return t.root6
}

// bitAt returns the i-th bit (MSB-first) from a 16-byte address representation.
// For IPv4, bits start at byte index 12 (the last 4 bytes of the 16-byte form).
func bitAt(b [16]byte, i int, is4 bool) uint8 {
	offset := 0
	if is4 {
		offset = 12
	}
	byteIdx := offset + i/8
	bitIdx := 7 - i%8
	return (b[byteIdx] >> bitIdx) & 1
}

// ipNetToPrefix converts a net.IPNet to a netip.Prefix.
// Returns ok=false if conversion fails.
func ipNetToPrefix(inet *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(inet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	ones, _ := inet.Mask.Size()
	bits := addr.BitLen()
	if ones > bits {
		ones = bits
	}
	return netip.PrefixFrom(addr, ones), true
}
