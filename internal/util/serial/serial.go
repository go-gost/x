package serial

import (
	"strconv"
	"strings"

	goserial "github.com/tarm/serial"
)

const (
	DefaultPort     = "COM1"
	DefaultBaudRate = 9600
	DefaultParity   = "none"
)

// COM1,9600,odd
func ParseConfigFromAddr(addr string) *goserial.Config {
	cfg := &goserial.Config{
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

func parseParity(s string) goserial.Parity {
	switch strings.ToLower(s) {
	case "o", "odd":
		return goserial.ParityOdd
	case "e", "even":
		return goserial.ParityEven
	case "m", "mark":
		return goserial.ParityMark
	case "s", "space":
		return goserial.ParitySpace
	default:
		return goserial.ParityNone
	}
}
