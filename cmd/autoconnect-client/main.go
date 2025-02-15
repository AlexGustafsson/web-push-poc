package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/AlexGustafsson/web-push-poc/internal/autoconnect"
	"github.com/AlexGustafsson/web-push-poc/internal/webpush"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <application server public key>\n", os.Args[0])
		os.Exit(1)
	}

	client, err := autoconnect.NewClient("wss://push.services.mozilla.com/")
	if err != nil {
		slog.Error("Failed to connect to push service", slog.Any("error", err))
		return
	}

	pushManager := webpush.NewPushManager(client)
	client.OnMessage(func(m autoconnect.Message) {
		switch m := m.(type) {
		case *autoconnect.NotificationMessage:
			data, err := base64.RawURLEncoding.DecodeString(m.Data)
			if err != nil {
				slog.Warn("Got invalid message body", slog.Any("error", err))
				return
			}

			message, err := pushManager.HandleMessage(m.ChannelID, data)
			if err != nil {
				slog.Warn("Failed to handle message", slog.Any("error", err))
				return
			}

			slog.Info("Got message", slog.String("message", string(message)))
		}
	})

	applicationServerPublicKeyBytes, err := base64.RawURLEncoding.DecodeString(os.Args[1])
	if err != nil {
		slog.Error("Invalid server key", slog.Any("error", err))
		return
	}

	applicationServerPublicKey, err := ecdh.P256().NewPublicKey(applicationServerPublicKeyBytes)
	if err != nil {
		slog.Error("Invalid server key", slog.Any("error", err))
		return
	}

	subscription, err := pushManager.Subscribe(applicationServerPublicKey)
	if err != nil {
		slog.Error("Failed to create subscription", slog.Any("error", err))
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(subscription)

	<-time.After(5 * time.Minute)
}
