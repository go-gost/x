package kcp

import (
	"crypto/sha1"
	"encoding/json"
	"os"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

var (
	// DefaultSalt is the default salt for KCP cipher.
	DefaultSalt = "kcp-go"
)

var (
	// DefaultKCPConfig is the default KCP config.
	DefaultConfig = &Config{
		Key:          "it's a secrect",
		Crypt:        "aes",
		Mode:         "fast",
		MTU:          1350,
		SndWnd:       1024,
		RcvWnd:       1024,
		DataShard:    10,
		ParityShard:  3,
		DSCP:         0,
		NoComp:       false,
		AckNodelay:   false,
		NoDelay:      0,
		Interval:     50,
		Resend:       0,
		NoCongestion: 0,
		SockBuf:      4194304,
		SmuxVer:      1,
		SmuxBuf:      4194304,
		StreamBuf:    2097152,
		KeepAlive:    10,
		SnmpLog:      "",
		SnmpPeriod:   60,
		Signal:       false,
		TCP:          false,
	}
)

// KCPConfig describes the config for KCP.
type Config struct {
	Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	SmuxBuf      int    `json:"smuxbuf"`
	StreamBuf    int    `json:"streambuf"`
	SmuxVer      int    `json:"smuxver"`
	KeepAlive    int    `json:"keepalive"`
	SnmpLog      string `json:"snmplog"`
	SnmpPeriod   int    `json:"snmpperiod"`
	Signal       bool   `json:"signal"` // Signal enables the signal SIGUSR1 feature.
	TCP          bool   `json:"tcp"`
}

func ParseFromFile(filename string) (*Config, error) {
	if filename == "" {
		return nil, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	if err = json.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}

// Init initializes the KCP config.
func (c *Config) Init() {
	switch c.Mode {
	case "normal":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 0, 40, 2, 1
	case "fast":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 0, 30, 2, 1
	case "fast2":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 1, 20, 2, 1
	case "fast3":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 1, 10, 2, 1
	}
	if c.SmuxVer <= 0 {
		c.SmuxVer = 1
	}
	if c.SmuxBuf <= 0 {
		c.SmuxBuf = c.SockBuf
	}
	if c.StreamBuf <= 0 {
		c.StreamBuf = c.SockBuf / 2
	}
}

func BlockCrypt(key, crypt, salt string) (block kcp.BlockCrypt) {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)

	switch crypt {
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "aes":
		fallthrough
	default: // aes
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return
}
