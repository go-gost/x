package forwarder

import "maps"

// Rewriter-plugin metadata common fields (JSON convention, opaque to
// core/plugin — carried in RewriteRequest.Metadata).
const (
	MetaKeySid       = "sid"
	MetaKeyDirection = "direction"
	MetaKeyURI       = "uri"
	MetaKeyKind      = "kind"
)

// Kind values: what the plugin is receiving (byte payload vs header block).
const (
	KindBody   = "body"
	KindHeader = "header"
)

// rewriteMeta builds the standard plugin metadata: sid/direction/uri/kind
// plus dimension-specific extras. Empty common fields are omitted so plugins
// can rely on presence rather than empty strings.
func rewriteMeta(sid, direction, uri, kind string, extras map[string]any) map[string]any {
	md := map[string]any{}
	if sid != "" {
		md[MetaKeySid] = sid
	}
	if direction != "" {
		md[MetaKeyDirection] = direction
	}
	if uri != "" {
		md[MetaKeyURI] = uri
	}
	if kind != "" {
		md[MetaKeyKind] = kind
	}
	maps.Copy(md, extras)
	return md
}
