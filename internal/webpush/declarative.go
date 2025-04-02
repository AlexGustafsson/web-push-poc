package webpush

// SEE: https://pr-preview.s3.amazonaws.com/w3c/push-api/pull/385.html#declarative-push-message
type DeclerativePushMessage struct {
	// WebPush MUST be set to 8030.
	WebPush      int                         `json:"web_push"`
	Notification DeclerativePushNotification `json:"notification"`
	AppBadge     uint64                      `json:"app_badge,omitempty"`
	Mutable      *bool                       `json:"mutable,omitempty"`
}

// SEE: https://pr-preview.s3.amazonaws.com/w3c/push-api/pull/385.html#declarative-push-message
type DeclerativePushNotification struct {
	Title              string                              `json:"title"`
	Navigate           string                              `json:"navigate"`
	Language           string                              `json:"lang,omitempty"`
	Direction          string                              `json:"ltr,omitempty"`
	Body               string                              `json:"body,omitempty"`
	Tag                string                              `json:"tag,omitempty"`
	Image              string                              `json:"image,omitempty"`
	Icon               string                              `json:"icon,omitempty"`
	Badge              string                              `json:"badge,omitempty"`
	Vibrate            []int                               `json:"vibrate,omitempty"`
	Timestamp          uint64                              `json:"timestamp,omitempty"`
	Renotify           *bool                               `json:"renotify,omitempty"`
	Silent             *bool                               `json:"silent,omitempty"`
	RequireInteraction *bool                               `json:"requireInteraction,omitempty"`
	Data               any                                 `json:"data,omitempty"`
	Actions            []DeclerativePushNotificationAction `json:"actions,omitempty"`
}

// SEE: https://pr-preview.s3.amazonaws.com/w3c/push-api/pull/385.html#declarative-push-message
type DeclerativePushNotificationAction struct {
	Action   string `json:"action"`
	Title    string `json:"title"`
	Navigate string `json:"navigate"`
	Icon     string `json:"icon,omitempty"`
}
