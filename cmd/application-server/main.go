package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/AlexGustafsson/web-push-poc/internal/webpush"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	applicationServer, err := webpush.NewApplicationServer()
	if err != nil {
		slog.Error("Failed to create application server", slog.Any("error", err))
		return
	}

	// MUST be set for Safari to work
	// SEE: https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers
	applicationServer.Subject = "https://example.com"

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/push", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Handling message")
		var request struct {
			Subscription webpush.Subscription `json:"subscription"`
			Message      string               `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		True := true
		False := false
		message := webpush.DeclerativePushMessage{
			WebPush: 8030,
			Notification: webpush.DeclerativePushNotification{
				Title:    "Notification",
				Navigate: "https://example.com",
				Body:     request.Message,
				Renotify: &True,
				Silent:   &False,
			},
		}
		content, err := json.Marshal(&message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Printf("%s\n", content)

		target, err := request.Subscription.PushTarget()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = applicationServer.Push(r.Context(), target, content, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	slog.Info("Started application server", slog.String("applicationServerPublicKey", applicationServer.PublicKeyString()))
	err = http.ListenAndServe(":8081", mux)
	if err != nil {
		slog.Error("Failed to serve", slog.Any("error", err))
		return
	}
}
