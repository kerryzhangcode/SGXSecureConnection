package handler

import (
	"fmt"
	"net"
	"crypto/sha256"
	
	"main/quote"
	"main/message"
	"main/key"
)

var conn *net.UDPConn

func HandleMessage(connection *net.UDPConn, msg message.Message, remoteAddr *net.UDPAddr) {
	conn = connection
	switch msg.Type {
		case message.MessageTypeText:
			handleTextMessage(msg, remoteAddr)
		case message.MessageTypeQuote:
			handleQuoteMessage(msg, remoteAddr)
		case message.MessageTypeQuoteRes:
			handleQuoteResMessage(msg, remoteAddr)
		default:
			fmt.Println("Unhandle Type:", msg.Content)
	}
}

func handleTextMessage(msg message.Message, remoteAddr *net.UDPAddr) {
	text := message.DecryptMessage(remoteAddr, msg)
	fmt.Println("Decrypted Plaintext:", string(text))
}

func handleQuoteMessage(msg message.Message, remoteAddr *net.UDPAddr) {
	fmt.Printf("Received message (Quote) from %s\n", remoteAddr.String())
	quote.VerifyQuote(msg)
	// Get remote key
	remotePublicKey, err := key.Curve.NewPublicKey(msg.PublicKey)
	if err != nil {
		fmt.Println("Error restoring remote public key:", err)
		return
	}

	// Get local keys
	privatekey, publicKey := key.GetAsymmetricKeys(remoteAddr)

	// Get symmetric key
	key.GenerateSymmetricKey(privatekey, remotePublicKey, remoteAddr)
	
	publicKeyHash := sha256.Sum256(publicKey.Bytes())
	localQuote := quote.GetQuote(publicKeyHash[:])
	message.SendMessage(conn, remoteAddr, message.Message{
		Type: message.MessageTypeQuoteRes,
		Content: localQuote,
		PublicKey: publicKey.Bytes(),
	})
}

func handleQuoteResMessage(msg message.Message, remoteAddr *net.UDPAddr) {
	fmt.Printf("Received message (QuoteRes) from %s\n", remoteAddr.String())
	quote.VerifyQuote(msg)

	remotePublicKey, err := key.Curve.NewPublicKey(msg.PublicKey)
	if err != nil {
		fmt.Println("Error restoring remote public key:", err)
		return
	}

	privateKey, _ := key.GetAsymmetricKeys(remoteAddr)
	key.GenerateSymmetricKey(privateKey, remotePublicKey,remoteAddr)
	
	encryptedMessage := message.EncryptMessage(remoteAddr, message.Message{
		Type: message.MessageTypeText,
		Content: [] byte("Quote exchanges finish"),
	})
	message.SendMessage(conn, remoteAddr, encryptedMessage)
}