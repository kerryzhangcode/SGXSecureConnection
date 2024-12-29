package client

import (
	"net"
	"crypto/ecdh"
)

type ClientInfo struct {
	Addr *net.UDPAddr
	PrivateKey *ecdh.PrivateKey
	PublicKey *ecdh.PublicKey
	Key [32] byte
	OriginKey [] byte
}

var (
	ClientMap = make(map[string]ClientInfo) // 存储客户端信息
	// mapMutex  sync.Mutex                   // 保证并发安全
)