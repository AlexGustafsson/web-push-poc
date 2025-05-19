package aes128gcm

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	// All values are Base64 URL-encoded, without padding
	testCases := []struct {
		Name               string
		Ciphertext         string
		ExpectedSalt       string
		ExpectedRecordSize uint32
		ExpectedKeyID      string
	}{
		{
			Name:               "RFC 8188 3.1",
			Ciphertext:         "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg",
			ExpectedSalt:       "I1BsxtFttlv3u_Oo94xnmw",
			ExpectedRecordSize: 4096,
			ExpectedKeyID:      "",
		},
		{
			Name:               "RFC 8188 3.2",
			Ciphertext:         "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA",
			ExpectedSalt:       "uNCkWiNYzKTnBN9ji3-qWA",
			ExpectedRecordSize: 25,
			ExpectedKeyID:      "YTE",
		},
		{
			Name:               "gauntface/simple-push-demo",
			Ciphertext:         "eQAMnLABzEBYh7vIcdkjeAAAEABBBPEbjQb2WmTSuXKrPjCJTexrAEJDwoivUPRJPb95QuENt0DLjKFsUh0W7YGVzh1YrPZWNIldVSg2qEJxKlH-N9GeyG6iTTeylMHxtpYk6iAHHrZ-9BN_E6yBWCtKOwQJ",
			ExpectedSalt:       "eQAMnLABzEBYh7vIcdkjeA",
			ExpectedRecordSize: 4096,
			ExpectedKeyID:      "BPEbjQb2WmTSuXKrPjCJTexrAEJDwoivUPRJPb95QuENt0DLjKFsUh0W7YGVzh1YrPZWNIldVSg2qEJxKlH-N9E",
		},
		{
			Name:               "web-push-libs",
			Ciphertext:         "lFIj-_UML_iEnPfvHM03HAAAEABBBCd8ZrreM0dG5wDW5Qqg4WwXpDbFaTBC1Ksk_Q6kA1m5jw5xRzkEMs0XN1seQzZG_ZACrMPVrdtPdq2ddG1xvzr-CAFutu47kl0p0a04LfizMFTzhWw_IpD0B_jouGJrxv8UpoCXpa1XYrx2h5N2yx2-Bp2mYaUpSE1CxGg5oZyNXVyH02qNuWN9H4PCX5bDJH6ob790Cxq1jKMHuUt977QE11O-RYyoIv1W1Hg",
			ExpectedSalt:       "lFIj-_UML_iEnPfvHM03HA",
			ExpectedRecordSize: 4096,
			ExpectedKeyID:      "BCd8ZrreM0dG5wDW5Qqg4WwXpDbFaTBC1Ksk_Q6kA1m5jw5xRzkEMs0XN1seQzZG_ZACrMPVrdtPdq2ddG1xvzo",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			ciphertext, err := base64.RawURLEncoding.DecodeString(testCase.Ciphertext)
			require.NoError(t, err)

			expectedSalt, err := base64.RawURLEncoding.DecodeString(testCase.ExpectedSalt)
			require.NoError(t, err)

			var expectedKeyID []byte
			if testCase.ExpectedKeyID != "" {
				expectedKeyID, err = base64.RawURLEncoding.DecodeString(testCase.ExpectedKeyID)
				require.NoError(t, err)
			}

			var header Header
			require.NoError(t, header.UnmarshalBinary(ciphertext))

			// Decoded header matches expectations
			assert.Equal(t, expectedSalt, header.Salt[:])
			assert.Equal(t, testCase.ExpectedRecordSize, header.RecordSize)
			assert.Equal(t, expectedKeyID, header.KeyID)

			// Encoded header matches expectations
			headerBytes, err := header.MarshalBinary()
			require.NoError(t, err)
			assert.Equal(t, ciphertext[:header.Length()], headerBytes)
		})
	}
}
