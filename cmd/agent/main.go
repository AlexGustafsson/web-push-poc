package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/AlexGustafsson/web-push-poc/internal/webpush"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	secret, err := base64.RawURLEncoding.DecodeString("OPMLk5kfCaEEVMz1cleOM8VdlCCThTlBv55f8ZsNnro")
	if err != nil {
		panic(err)
	}

	agent := &Agent{
		PushEndpoint: "http://localhost:8082/push",
		Secret:       secret,
	}

	// TODO: The push manager interface isn't that nice for what we're trying to
	// do here. Essentially, the agent would like to access the manager's handle
	// message function. Ugly circular dependency in this case
	pushManager := webpush.NewPushManager(agent)
	agent.Manager = pushManager

	pushServer := webpush.NewPushServer(agent)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /subscribe", func(w http.ResponseWriter, r *http.Request) {
		content, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		bytes, err := base64.RawURLEncoding.DecodeString(string(content))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		applicationServerPublickey, err := ecdh.P256().NewPublicKey(bytes)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		subscription, err := pushManager.Subscribe(applicationServerPublickey)
		if err != nil {
			slog.Error("Failed to create subscription", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.Encode(subscription)
	})

	mux.Handle("/", pushServer)

	if err := http.ListenAndServe(":8082", mux); err != nil {
		slog.Error("Failed to serve", slog.Any("error", err))
		return
	}
}
