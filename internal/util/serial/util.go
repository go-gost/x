package serial

import (
	"strconv"
	"strings"
)

const (
	DefaultPort     = "COM1"
	DefaultBaudRate = 9600
)

// COM1,9600,odd
func ParseConfigFromAddr(addr string) *Config {
	cfg := &Config{
		Name: DefaultPort,
		Baud: DefaultBaudRate,
	}
	ss := strings.Split(addr, ",")
	switch len(ss) {
	case 1:
		cfg.Name = ss[0]
	case 2:
		cfg.Name = ss[0]
		cfg.Baud, _ = strconv.Atoi(ss[1])
	case 3:
		cfg.Name = ss[0]
		cfg.Baud, _ = strconv.Atoi(ss[1])
		cfg.Parity = parseParity(ss[2])
	}
	return cfg
}

func AddrFromConfig(cfg *Config) string {
	ss := []string{
		cfg.Name,
		strconv.Itoa(cfg.Baud),
	}

	switch cfg.Parity {
	case ParityEven:
		ss = append(ss, "even")
	case ParityOdd:
		ss = append(ss, "odd")
	case ParityMark:
		ss = append(ss, "mark")
	case ParitySpace:
		ss = append(ss, "space")
	}
	return strings.Join(ss, ",")
}

func parseParity(s string) Parity {
	switch strings.ToLower(s) {
	case "o", "odd":
		return ParityOdd
	case "e", "even":
		return ParityEven
	case "m", "mark":
		return ParityMark
	case "s", "space":
		return ParitySpace
	default:
		return ParityNone
	}
}
