package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
)

type Handler struct {
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("new %s request\n", r.Method)
	fmt.Printf("request headers:\n")

	for k, v := range r.Header {
		fmt.Printf("%s: %v\n", k, v)
	}

	fmt.Println()

	if r.Header.Get("Connection") == "Upgrade" && r.Header.Get("Upgrade") == "websocket" {
		h.handleWebsocketUpgrade(w, r)
	}
}

func (h *Handler) handleWebsocketUpgrade(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		fmt.Println("request does not contain websocket handshake key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	extensions := r.Header.Get("Sec-Websocket-Extensions")
	if extensions != "" {
		fmt.Printf("websocket extensions offered by client: %s\n", extensions)
	} else {
		fmt.Println("websocket client offered no extensions")
	}

	hash := hashHandshakeKey(key)
	fmt.Printf("websocket handshake key: %s\n", key)
	fmt.Printf("websocket accept key: %s\n", hash)

	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\n")
	bufrw.WriteString("Connection: Upgrade\n")
	bufrw.WriteString("Upgrade: websocket\n")
	bufrw.WriteString("Sec-Websocket-Accept: " + hash + "\n\n")
	bufrw.Flush()

	decoder := Decoder{Mask: true}
	for {
		fmt.Println("decode new frame")
		frame, err := decoder.Decode(bufrw)
		if err != nil {
			fmt.Printf("decode frame: %v\n", err)
			return
		}
		fmt.Println()

		_ = frame
	}
}

const handshakeMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func hashHandshakeKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(handshakeMagic))
	return string(base64.StdEncoding.AppendEncode(nil, h.Sum(nil)))
}

func main() {
	s := http.Server{
		Addr:    ":1076",
		Handler: &Handler{},
	}
	err := s.ListenAndServe()
	if err != nil {
		fmt.Println("server exit:", err)
	}
}
