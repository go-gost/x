// Package util provides typed accessor functions for reading values from a
// metadata.Metadata store. Each getter accepts one or more fallback keys and
// returns the first match. All functions are nil-safe on the metadata argument.
package util

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-gost/core/metadata"
)

// IsExists reports whether at least one of the given keys is present in md.
// Returns false if md is nil.
func IsExists(md metadata.Metadata, keys ...string) bool {
	if md == nil {
		return false
	}

	for _, key := range keys {
		if md.IsExists(key) {
			return true
		}
	}
	return false
}

// GetBool returns the bool value for the first matching key. String values are
// parsed with strconv.ParseBool, and non-zero integers are treated as true.
// Returns false if md is nil or no key matches.
func GetBool(md metadata.Metadata, keys ...string) (v bool) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}
		switch vv := md.Get(key).(type) {
		case bool:
			v = vv
		case int:
			v = vv != 0
		case string:
			v, _ = strconv.ParseBool(vv)
		}
		break
	}

	return
}

// GetInt returns the int value for the first matching key. String values are
// parsed with strconv.Atoi, and true/false booleans are treated as 1/0.
// Returns 0 if md is nil or no key matches.
func GetInt(md metadata.Metadata, keys ...string) (v int) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}
		switch vv := md.Get(key).(type) {
		case bool:
			if vv {
				v = 1
			}
		case int:
			v = vv
		case string:
			v, _ = strconv.Atoi(vv)
		}
		break
	}

	return
}

// GetFloat returns the float64 value for the first matching key. String values
// are parsed with strconv.ParseFloat, float32 values are promoted, and int
// values are converted. Returns 0 if md is nil or no key matches.
func GetFloat(md metadata.Metadata, keys ...string) (v float64) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}

		switch vv := md.Get(key).(type) {
		case float32:
			v = float64(vv)
		case float64:
			v = vv
		case int:
			v = float64(vv)
		case string:
			v, _ = strconv.ParseFloat(vv, 64)
		}
		break
	}
	return
}

// GetDuration returns the time.Duration value for the first matching key.
// String values are parsed with time.ParseDuration; if that fails they are
// retried as integer seconds via strconv.Atoi. Integer values are treated as
// seconds. Returns 0 if md is nil or no key matches.
func GetDuration(md metadata.Metadata, keys ...string) (v time.Duration) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}

		switch vv := md.Get(key).(type) {
		case int:
			v = time.Duration(vv) * time.Second
		case string:
			v, _ = time.ParseDuration(vv)
			if v == 0 {
				n, _ := strconv.Atoi(vv)
				v = time.Duration(n) * time.Second
			}
		}
		break
	}
	return
}

// GetString returns the string value for the first matching key. Non-string
// values (int, int64, uint, uint64, bool, float32, float64) are formatted via
// strconv. Returns "" if md is nil or no key matches.
func GetString(md metadata.Metadata, keys ...string) (v string) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}

		switch vv := md.Get(key).(type) {
		case string:
			v = vv
		case int:
			v = strconv.FormatInt(int64(vv), 10)
		case int64:
			v = strconv.FormatInt(vv, 10)
		case uint:
			v = strconv.FormatUint(uint64(vv), 10)
		case uint64:
			v = strconv.FormatUint(uint64(vv), 10)
		case bool:
			v = strconv.FormatBool(vv)
		case float32:
			v = strconv.FormatFloat(float64(vv), 'f', -1, 32)
		case float64:
			v = strconv.FormatFloat(float64(vv), 'f', -1, 64)
		}
		break
	}

	return
}

// GetStrings returns the []string value for the first matching key. []any
// slices are converted element-by-element, skipping non-string values.
// Returns nil if md is nil or no key matches.
func GetStrings(md metadata.Metadata, keys ...string) (ss []string) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}

		switch v := md.Get(key).(type) {
		case []string:
			ss = v
		case []any:
			for _, vv := range v {
				if s, ok := vv.(string); ok {
					ss = append(ss, s)
				}
			}
		}
		break
	}
	return
}

// GetStringMap returns the map[string]any value for the first matching key.
// map[any]any values are converted by formatting keys with %v. Returns nil if
// md is nil or no key matches.
func GetStringMap(md metadata.Metadata, keys ...string) (m map[string]any) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}

		switch vv := md.Get(key).(type) {
		case map[string]any:
			m = vv
		case map[any]any:
			m = make(map[string]any)
			for k, v := range vv {
				m[fmt.Sprintf("%v", k)] = v
			}
		}
		break
	}
	return
}

// GetStringMapString returns the map[string]string value for the first matching
// key. Both map[string]any and map[any]any values are converted by formatting
// values with %v. Returns nil if md is nil or no key matches.
func GetStringMapString(md metadata.Metadata, keys ...string) (m map[string]string) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}

		switch vv := md.Get(key).(type) {
		case map[string]any:
			m = make(map[string]string)
			for k, v := range vv {
				m[k] = fmt.Sprintf("%v", v)
			}
		case map[any]any:
			m = make(map[string]string)
			for k, v := range vv {
				m[fmt.Sprintf("%v", k)] = fmt.Sprintf("%v", v)
			}
		}
		break
	}

	return
}
