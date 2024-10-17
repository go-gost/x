package util

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-gost/core/metadata"
)

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

func GetFloat(md metadata.Metadata, keys ...string) (v float64) {
	if md == nil {
		return
	}

	for _, key := range keys {
		if !md.IsExists(key) {
			continue
		}

		switch vv := md.Get(key).(type) {
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
