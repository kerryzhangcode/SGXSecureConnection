package main

import (
	"fmt"
	"net"
	"sync"
	"os"
	"encoding/json"
	"crypto/sha256"
	
	"main/quote"
	"main/message"
	"main/key"
	"main/handler"
)

const host = "127.0.0.1"
var (
	localPort  string
	remotePort *string
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
	conn       *net.UDPConn // 全局 conn
	wg         sync.WaitGroup
)

func main() {
	localPort, remotePort = getConf()
	localAddr = getUDPAddr(localPort)

	startUDPServer(localAddr)
	defer conn.Close()
    
	// If set remote, start connection
	if remotePort != nil {
		remoteAddr = getUDPAddr(*remotePort)
		handleInitialConnection(remoteAddr)
	}

	// wg.Add(1)
	// go listenConnection()
	// wg.Wait()
	listenConnection()
}

func handleInitialConnection(remoteAddr *net.UDPAddr) {
	_, publicKey := key.GetAsymmetricKeys(remoteAddr)

	publicKeyHash := sha256.Sum256(publicKey.Bytes())
	localQuote := quote.GetQuote(publicKeyHash[:])

	// start key exchange
	message.SendMessage(conn, remoteAddr, message.Message{
		Type: message.MessageTypeQuote,
		Content: localQuote,
		PublicKey: publicKey.Bytes(),
	})
}

func listenConnection() {
	// defer wg.Done()
	for {
		handleConnection()
	}
}

func getUDPAddr(port string) *net.UDPAddr{
	addr, err := net.ResolveUDPAddr("udp", host + ":" + port)
	if err != nil {
		fmt.Println("Error resolving address:", err)
		return nil
	}
	return addr
}

func getConf() (string, *string) {
	// Default port
	if len(os.Args) < 2 {
		return "8080", nil
	}
	// First as local port
	localPort := os.Args[1]
	// Second as remote port
	remotePort := os.Args[2]
	return localPort, &remotePort
}

func startUDPServer(addr *net.UDPAddr) {
	// Listen localhost
	var err error
	conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error starting UDP server:", err)
		return
	}
	fmt.Printf("UDP server listening on %s\n", addr)
}

func handleConnection() {
	buf := make([]byte, 1024*8)
	for {
		// Read UDP data
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading from UDP:", err)
			return
		}
		// Parse to meesage
		var msg message.Message
        err = json.Unmarshal(buf[:n], &msg)
		if err != nil {
            fmt.Println("Error parsing message:", err)
            return
        }
		// Process
		handler.HandleMessage(conn, msg, remoteAddr)
	}
}