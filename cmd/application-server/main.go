package main

import (
	"encoding/json"
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

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/push", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Handling message")
		var request struct {
			Subscription webpush.Subscription `json:"subscription"`
			Message      string               `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		target, err := request.Subscription.PushTarget()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		applicationServer.Push(r.Context(), target, []byte(request.Message), nil)
	})

	slog.Info("Started application server", slog.String("applicationServerPublicKey", applicationServer.PublicKeyString()))
	err = http.ListenAndServe(":8081", mux)
	if err != nil {
		slog.Error("Failed to serve", slog.Any("error", err))
		return
	}
}
