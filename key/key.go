package key

import (
	"fmt"
	"net"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"

	"main/client"
)

var Curve = ecdh.P256()

func GenerateSymmetricKey(privateKey *ecdh.PrivateKey, remotePublicKey *ecdh.PublicKey, remoteAddr *net.UDPAddr) {
	key, err := privateKey.ECDH(remotePublicKey)
	if err != nil {
		fmt.Println("Error calculating Alice's shared key:", err)
		return
	}
	c := client.ClientMap[remoteAddr.String()]
	c.OriginKey = key
	derivedKey := sha256.Sum256(key)
	c.Key = derivedKey
	client.ClientMap[remoteAddr.String()] = c
}

func GetAsymmetricKeys(remoteAddr *net.UDPAddr) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	c := client.ClientMap[remoteAddr.String()]
	privateKey := c.PrivateKey
	publicKey := c.PublicKey
	if privateKey== nil || publicKey == nil {
		// Generate local keys
		var err error
		privateKey, err = Curve.GenerateKey(rand.Reader)
		publicKey = privateKey.PublicKey()
		if err != nil {
			fmt.Println("Error generating privateKey:", err)
			panic(err)
		}
		c.PublicKey = publicKey
		c.PrivateKey = privateKey
		client.ClientMap[remoteAddr.String()] = c
	}
	return privateKey, publicKey
}

func GetSymmetricKey(remoteAddr  *net.UDPAddr) [32] byte {
	c := client.ClientMap[remoteAddr.String()]
	return c.Key
}