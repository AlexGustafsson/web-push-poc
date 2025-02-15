package webpush

import (
	"io"
	"net/http"
	"strconv"
)

// PushServer is (intended) to serve spec-compliant APIs for Web Push
// functionality.
// TODO: Only implement the PUSH endpoint in this package?
// subscription/unsubscription is not mandated by the RFC?
type PushServer struct {
	mux    *http.ServeMux
	pusher Pusher
}

// TODO: The RFC doesn't seem to be widely used in practice, except for the push
// endpoint. Likely due to user agents and push services being from the same
// vendor, largely making the spec irrelevant. In practice, everything is
// interoperable as long as the push endpoint is supported
func NewPushServer(pusher Pusher) *PushServer {
	server := &PushServer{
		mux:    http.NewServeMux(),
		pusher: pusher,
	}

	// NOTE: They way I'm reading the RFC, the push endpoint is the only one that
	// is mandated / properly specified? The subscribe endpoint is vague and
	// speaks in general terms. There is no unsubscribe endpoint. Mozilla doesn't
	// follow this spec, each user agent implements their own methods?
	server.mux.HandleFunc("POST /push/{token}", server.postPush)
	server.mux.HandleFunc("DELETE /message/{messageId}", server.deleteMessage)

	return server
}

func (s *PushServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *PushServer) postPush(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	ttlString := r.Header.Get("TTL")
	if ttlString == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	ttl, err := strconv.ParseInt(ttlString, 10, 32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	urgency := r.Header.Get("Urgency")
	if urgency != "" && urgency != "very-low" && urgency != "low" && urgency != "normal" && urgency != "high" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	topic := r.Header.Get("Topic")

	contentLengthString := r.Header.Get("Content-Length")
	if contentLengthString == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	contentLength, err := strconv.ParseInt(contentLengthString, 10, 32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// TODO: Make max content-type configurable?
	content := make([]byte, contentLength)
	_, err = io.ReadFull(r.Body, content)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	request := PushRequest{
		Token:       token,
		TTL:         int(ttl),
		Topic:       topic,
		ContentType: r.Header.Get("Content-Type"),
		Content:     content,
	}

	// TODO: What type of interface do we want for implementers here?
	// Include actual HTTP request as well, and let the handler write to the body?
	if err := s.pusher.Push(&request); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (s *PushServer) deleteMessage(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}
