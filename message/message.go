package message

import (
	"fmt"
	"net"
	"encoding/json"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"

	"main/key"
)


type Message struct {
	Type    MessageType `json:"type"`
	Content [] byte `json:"content"`
	Nonce [] byte `json:"nonce"`
	PublicKey [] byte `json:"publickey"`
}

type MessageType string
const (
	MessageTypeText  MessageType = "TEXT"
	MessageTypeQuote MessageType = "QUOTE"
	MessageTypeQuoteRes MessageType = "QUOTERES"
)


func EncryptMessage(remoteAddr  *net.UDPAddr, msg Message) Message {
	key := key.GetSymmetricKey(remoteAddr)
	// random nonce
	nonce := make([]byte, 12) // GCM 标准推荐 12 字节 nonce
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// AES-GCM encrytion
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// encrypt
	msg.Content = aesGCM.Seal(nil, nonce, msg.Content, nil)
	msg.Nonce = nonce
	return msg
}

func DecryptMessage(remoteAddr *net.UDPAddr, msg Message) [] byte {
	key := key.GetSymmetricKey(remoteAddr)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// decrypt
	plaintext, err := aesGCM.Open(nil, msg.Nonce, msg.Content, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

func SendMessage(conn *net.UDPConn, remoteAddr *net.UDPAddr, msg Message) {
	// Parse message to json
	jsonData, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	// Send message to remote server
	_, err = conn.WriteToUDP(jsonData, remoteAddr)
	if err != nil {
		fmt.Println("Error sending message:", err)
		return
	}
}