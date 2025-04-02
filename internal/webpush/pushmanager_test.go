package webpush

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubscriptionKeysPublicKey(t *testing.T) {
	testCases := []struct {
		Name   string
		P256DH string
		Error  error
	}{
		{
			Name:   "Safari",
			P256DH: "BBZpjmYPFEP5KoJOu7q1uA7tulOEk_pwueFKzFjnuTlytto8pLnbhyIOnPWlx4kOxAc3N8n8WMCRmo-TepfSuQ0",
			Error:  nil,
		},
		{
			Name:   "Firefox",
			P256DH: "BECssUMYvdgbpHmQVukvRchqWk2x6rZAhQViSdnJlswn_9UWfosTIQ_p7isJQrbaejexTCP2BYvZNrk5ZFoR3KI",
			Error:  nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(t.Name(), func(t *testing.T) {
			subscriptionKeys := &SubscriptionKeys{
				P256DH: testCase.P256DH,
			}

			_, err := subscriptionKeys.PublicKey()
			assert.Equal(t, testCase.Error, err)
		})
	}
}
