package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/gorilla/websocket"
)

func main() {
	upgrader := &websocket.Upgrader{
		Subprotocols: []string{},
	}

	http.ListenAndServeTLS(":8080", "localhost.pem", "localhost-key.pem", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("Failed to upgrade WebSocket", slog.Any("error", err))
			return
		}

		requestHeader := http.Header{
			"User-Agent": r.Header["User-Agent"],
		}

		proxy(conn, requestHeader)
	}))
}

func proxy(conn *websocket.Conn, requestHeader http.Header) {

	upstream, _, err := websocket.DefaultDialer.Dial("wss://push.services.mozilla.com/", requestHeader)
	if err != nil {
		slog.Error("Failed to connect to upstream", slog.Any("error", err))
		conn.Close()
		return
	}

	// conn -> upstrean
	go func() {
		defer upstream.Close()

		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				slog.Error("Failed to read message", slog.Any("error", err))
				return
			}

			fmt.Fprintln(os.Stderr, "Firefox -> Server")
			fmt.Fprintf(os.Stdout, "%s\n", message)

			err = upstream.WriteMessage(messageType, message)
			if err != nil {
				slog.Error("Failed to send message", slog.Any("error", err))
				return
			}
		}
	}()

	// conn <- upstream
	go func() {
		defer conn.Close()

		for {
			messageType, message, err := upstream.ReadMessage()
			if err != nil {
				slog.Error("Failed to read message", slog.Any("error", err))
				return
			}

			fmt.Fprintln(os.Stderr, "Firefox <- Server")
			fmt.Fprintf(os.Stdout, "%s\n", message)

			err = conn.WriteMessage(messageType, message)
			if err != nil {
				slog.Error("Failed to send message", slog.Any("error", err))
				return
			}
		}
	}()
}
