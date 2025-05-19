package aes128gcm

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	// All values are Base64 URL-encoded, without padding
	testCases := []struct {
		Name                string
		Plaintext           string
		InputKeyingMaterial string
		Salt                string
		KeyID               string
		RecordSize          int
		ExpectedCiphertext  string
	}{
		{
			Name:                "RFC 8188 3.1",
			Plaintext:           "SSBhbSB0aGUgd2FscnVz",
			InputKeyingMaterial: "yqdlZ-tYemfogSmv7Ws5PQ",
			Salt:                "I1BsxtFttlv3u_Oo94xnmw",
			KeyID:               "",
			RecordSize:          4096,
			ExpectedCiphertext:  "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg",
		},
		{
			Name:                "RFC 8188 3.2",
			Plaintext:           "SSBhbSB0aGUgd2FscnVz",
			InputKeyingMaterial: "BO3ZVPxUlnLORbVGMpbT1Q",
			Salt:                "uNCkWiNYzKTnBN9ji3-qWA",
			KeyID:               "YTE",
			RecordSize:          25,
			// NOTE: This test is slightly different than the spec as the
			// implementation doesn't use a pad byte in the first record
			// ExpectedCiphertext:  "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA",
			ExpectedCiphertext: "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gn2gI0ofGmv5f-6AkiuXzlWpUMkQzygrZXO6L-z5uKh9iiBcajZ_n9e5IG",
		},
		{
			Name:                "RFC 8291 Appendix A",
			Plaintext:           "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24",
			InputKeyingMaterial: "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg",
			Salt:                "DGv6ra1nlYgDCS1FRnbzlw",
			KeyID:               "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
			RecordSize:          4096,
			ExpectedCiphertext:  "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
		},
		{
			Name:                "gauntface/simple-push-demo",
			Plaintext:           base64.RawURLEncoding.EncodeToString([]byte("weattackatdawn")),
			InputKeyingMaterial: "b6zpwBJpyjx2c3Dq5QAYzgJZX-R59KpfBBNglKExK3I",
			Salt:                "eQAMnLABzEBYh7vIcdkjeA",
			KeyID:               "BPEbjQb2WmTSuXKrPjCJTexrAEJDwoivUPRJPb95QuENt0DLjKFsUh0W7YGVzh1YrPZWNIldVSg2qEJxKlH-N9E",
			RecordSize:          4096,
			ExpectedCiphertext:  "eQAMnLABzEBYh7vIcdkjeAAAEABBBPEbjQb2WmTSuXKrPjCJTexrAEJDwoivUPRJPb95QuENt0DLjKFsUh0W7YGVzh1YrPZWNIldVSg2qEJxKlH-N9GeyG6iTTeylMHxtpYk6iAHHrZ-9BN_E6yBWCtKOwQJ",
		},
		{
			Name:                "Declerative Web Push regression test",
			Plaintext:           base64.RawURLEncoding.EncodeToString([]byte(`{"web_push":8030,"notification":{"title":"Notification","navigate":"https://example.com","body":"Hello"}}`)),
			InputKeyingMaterial: "SwfgrfPa4hdK7Bn2SIy36SWKqnsxdIdJlOT4olAI7is",
			Salt:                "pkeNWI6mDrK-HsHUccmcKw",
			KeyID:               "BFyejXlMoxgdB6ReIFrpQJTtSObkhHPYGhbNv7XwLcDGh6x2CVCbG2RUq-nuZU1A5kIjAjIesc7f1v1y2eNhD1s",
			RecordSize:          4096,
			ExpectedCiphertext:  "pkeNWI6mDrK-HsHUccmcKwAAEABBBFyejXlMoxgdB6ReIFrpQJTtSObkhHPYGhbNv7XwLcDGh6x2CVCbG2RUq-nuZU1A5kIjAjIesc7f1v1y2eNhD1tlELUKtIywzjlqEtmnhAaaQDtQUcMkVMcr3R_eH0o9OtHSp212Um3Ht_D5Ka2QzhJdf8gbXGumxkvBhpuQRq7ROBsYn-ZtZkGJ5cyZvD9oImkZfv3D7xuh5tD9ozZYv5D3AlPMIiqgLVTPeDRdEYGCF53SwxLwWGylAg",
		},
		{
			Name:                "web-push-libs",
			Plaintext:           base64.RawURLEncoding.EncodeToString([]byte(`{"web_push":8030,"notification":{"title":"Hello, World!","navigate":"https://example.com"}}`)),
			InputKeyingMaterial: "cHUxzkyPrxX8LEizP12yr9ZCCkPAM-OXb5yW_iEvGPI",
			Salt:                "lFIj-_UML_iEnPfvHM03HA",
			KeyID:               "BCd8ZrreM0dG5wDW5Qqg4WwXpDbFaTBC1Ksk_Q6kA1m5jw5xRzkEMs0XN1seQzZG_ZACrMPVrdtPdq2ddG1xvzo",
			RecordSize:          4096,
			ExpectedCiphertext:  "lFIj-_UML_iEnPfvHM03HAAAEABBBCd8ZrreM0dG5wDW5Qqg4WwXpDbFaTBC1Ksk_Q6kA1m5jw5xRzkEMs0XN1seQzZG_ZACrMPVrdtPdq2ddG1xvzr-CAFutu47kl0p0a04LfizMFTzhWw_IpD0B_jouGJrxv8UpoCXpa1XYrx2h5N2yx2-Bp2mYaUpSE1CxGg5oZyNXVyH02qNuWN9H4PCX5bDJH6ob790Cxq1jKMHuUt977QE11O-RYyoIv1W1Hg",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			plaintext, err := base64.RawURLEncoding.DecodeString(testCase.Plaintext)
			require.NoError(t, err)

			ikm, err := base64.RawURLEncoding.DecodeString(testCase.InputKeyingMaterial)
			require.NoError(t, err)

			salt, err := base64.RawURLEncoding.DecodeString(testCase.Salt)
			require.NoError(t, err)

			var keyID []byte
			if testCase.KeyID != "" {
				keyID, err = base64.RawURLEncoding.DecodeString(testCase.KeyID)
				require.NoError(t, err)
			}

			expectedCiphertext, err := base64.RawURLEncoding.DecodeString(testCase.ExpectedCiphertext)
			require.NoError(t, err)

			ciphertext, err := Encrypt(plaintext, ikm, salt, keyID, testCase.RecordSize)
			require.NoError(t, err)

			assert.Equal(t, expectedCiphertext, ciphertext)
		})
	}
}

func TestDecrypt(t *testing.T) {
	// All values are Base64 URL-encoded, without padding
	testCases := []struct {
		Name                string
		Ciphertext          string
		InputKeyingMaterial string
		ExpectedPlaintext   string
	}{
		{
			Name:                "RFC 8188 3.1",
			Ciphertext:          "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg",
			InputKeyingMaterial: "yqdlZ-tYemfogSmv7Ws5PQ",
			ExpectedPlaintext:   "SSBhbSB0aGUgd2FscnVz",
		},
		{
			Name:                "RFC 8188 3.2",
			Ciphertext:          "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA",
			InputKeyingMaterial: "BO3ZVPxUlnLORbVGMpbT1Q",
			ExpectedPlaintext:   "SSBhbSB0aGUgd2FscnVz",
		},
		{
			Name:                "gauntface/simple-push-demo",
			Ciphertext:          "eQAMnLABzEBYh7vIcdkjeAAAEABBBPEbjQb2WmTSuXKrPjCJTexrAEJDwoivUPRJPb95QuENt0DLjKFsUh0W7YGVzh1YrPZWNIldVSg2qEJxKlH-N9GeyG6iTTeylMHxtpYk6iAHHrZ-9BN_E6yBWCtKOwQJ",
			InputKeyingMaterial: "b6zpwBJpyjx2c3Dq5QAYzgJZX-R59KpfBBNglKExK3I",
			ExpectedPlaintext:   base64.RawURLEncoding.EncodeToString([]byte("weattackatdawn")),
		},
		{
			Name:                "Declerative Web Push regression test",
			Ciphertext:          "pkeNWI6mDrK-HsHUccmcKwAAEABBBFyejXlMoxgdB6ReIFrpQJTtSObkhHPYGhbNv7XwLcDGh6x2CVCbG2RUq-nuZU1A5kIjAjIesc7f1v1y2eNhD1tlELUKtIywzjlqEtmnhAaaQDtQUcMkVMcr3R_eH0o9OtHSp212Um3Ht_D5Ka2QzhJdf8gbXGumxkvBhpuQRq7ROBsYn-ZtZkGJ5cyZvD9oImkZfv3D7xuh5tD9ozZYv5D3AlPMIiqgLVTPeDRdEYGCF53SwxLwWGylAg",
			InputKeyingMaterial: "SwfgrfPa4hdK7Bn2SIy36SWKqnsxdIdJlOT4olAI7is",
			ExpectedPlaintext:   base64.RawURLEncoding.EncodeToString([]byte(`{"web_push":8030,"notification":{"title":"Notification","navigate":"https://example.com","body":"Hello"}}`)),
		},
		{
			Name:                "web-push-libs",
			Ciphertext:          "lFIj-_UML_iEnPfvHM03HAAAEABBBCd8ZrreM0dG5wDW5Qqg4WwXpDbFaTBC1Ksk_Q6kA1m5jw5xRzkEMs0XN1seQzZG_ZACrMPVrdtPdq2ddG1xvzr-CAFutu47kl0p0a04LfizMFTzhWw_IpD0B_jouGJrxv8UpoCXpa1XYrx2h5N2yx2-Bp2mYaUpSE1CxGg5oZyNXVyH02qNuWN9H4PCX5bDJH6ob790Cxq1jKMHuUt977QE11O-RYyoIv1W1Hg",
			InputKeyingMaterial: "cHUxzkyPrxX8LEizP12yr9ZCCkPAM-OXb5yW_iEvGPI",
			ExpectedPlaintext:   base64.RawURLEncoding.EncodeToString([]byte(`{"web_push":8030,"notification":{"title":"Hello, World!","navigate":"https://example.com"}}`)),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			ciphertext, err := base64.RawURLEncoding.DecodeString(testCase.Ciphertext)
			require.NoError(t, err)

			ikm, err := base64.RawURLEncoding.DecodeString(testCase.InputKeyingMaterial)
			require.NoError(t, err)

			expectedPlaintext, err := base64.RawURLEncoding.DecodeString(testCase.ExpectedPlaintext)
			require.NoError(t, err)

			plaintext, err := Decrypt(ciphertext, ikm)
			require.NoError(t, err)

			assert.Equal(t, expectedPlaintext, plaintext)
		})
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	// Some arbitrary sizes
	dataSizes := []int{
		8, 16, 32, 64, 128, 512, 1024, 2048, 4096,
	}
	recordSizes := []int{
		18, 32, 64, 128, 512, 1024, 2048, 4096,
	}
	keyIDSizes := []int{
		0, 1, 2, 3, 4,
	}

	var ikm [16]byte
	_, err := rand.Read(ikm[:])
	require.NoError(t, err)

	var salt [16]byte
	_, err = rand.Read(salt[:])
	require.NoError(t, err)

	for _, dataSize := range dataSizes {
		for _, recordSize := range recordSizes {
			for _, keyIDSize := range keyIDSizes {
				t.Run(fmt.Sprintf("Roundtrip %dB of data, %dB records, %dB key id", dataSize, recordSize, keyIDSize), func(t *testing.T) {
					plaintext := make([]byte, dataSize)

					var keyID []byte
					if keyIDSize > 0 {
						keyID = make([]byte, keyIDSize)
						_, err = rand.Read(salt[:])
						require.NoError(t, err)
					}

					ciphertext, err := Encrypt(plaintext, ikm[:], salt[:], keyID, recordSize)
					require.NoError(t, err)

					actualPlaintext, err := Decrypt(ciphertext, ikm[:])
					require.NoError(t, err)

					assert.Equal(t, plaintext, actualPlaintext)
				})
			}
		}
	}
}

func TestDeriveNonce(t *testing.T) {
	// All values are Base64 URL-encoded, without padding
	testCases := []struct {
		Name                 string
		RecordSequenceNumber string
		InputKeyingMaterial  string
		Salt                 string
		ExpectedNonce        string
	}{
		{
			Name:                 "RFC 8188 3.1",
			RecordSequenceNumber: "AAAAAAAAAAAAAAAA",
			InputKeyingMaterial:  "yqdlZ-tYemfogSmv7Ws5PQ",
			Salt:                 "I1BsxtFttlv3u_Oo94xnmw",
			ExpectedNonce:        "Bcs8gkIRKLI8GeI8",
		},
		{
			Name:                 "RFC 8188 3.2, record 0",
			RecordSequenceNumber: "AAAAAAAAAAAAAAAA",
			InputKeyingMaterial:  "BO3ZVPxUlnLORbVGMpbT1Q",
			Salt:                 "uNCkWiNYzKTnBN9ji3-qWA",
			ExpectedNonce:        "VqylG1rdt-mJrNgP",
		},
		{
			Name:                 "RFC 8188 3.2, record 1",
			RecordSequenceNumber: "AAAAAAAAAAAAAAAB",
			InputKeyingMaterial:  "BO3ZVPxUlnLORbVGMpbT1Q",
			Salt:                 "uNCkWiNYzKTnBN9ji3-qWA",
			ExpectedNonce:        "VqylG1rdt-mJrNgO",
		},
		{
			Name:                 "RFC 8291 Appendix A",
			RecordSequenceNumber: "AAAAAAAAAAAAAAAA",
			InputKeyingMaterial:  "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg",
			Salt:                 "DGv6ra1nlYgDCS1FRnbzlw",
			ExpectedNonce:        "4h_95klXJ5E_qnoN",
		},
		{
			Name:                 "gauntface/simple-push-demo",
			RecordSequenceNumber: "AAAAAAAAAAAAAAAA",
			InputKeyingMaterial:  "b6zpwBJpyjx2c3Dq5QAYzgJZX-R59KpfBBNglKExK3I",
			Salt:                 "eQAMnLABzEBYh7vIcdkjeA",
			ExpectedNonce:        "R_pz_3ePXEqQqhfs",
		},
		{
			Name:                 "web-push-libs",
			RecordSequenceNumber: "AAAAAAAAAAAAAAAA",
			InputKeyingMaterial:  "cHUxzkyPrxX8LEizP12yr9ZCCkPAM-OXb5yW_iEvGPI",
			Salt:                 "lFIj-_UML_iEnPfvHM03HA",
			ExpectedNonce:        "6hrNswPbJmpPExIw",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			recordSequenceNumber, err := base64.RawURLEncoding.DecodeString(testCase.RecordSequenceNumber)
			require.NoError(t, err)

			inputKeyingMaterial, err := base64.RawURLEncoding.DecodeString(testCase.InputKeyingMaterial)
			require.NoError(t, err)

			salt, err := base64.RawURLEncoding.DecodeString(testCase.Salt)
			require.NoError(t, err)

			expectedNonce, err := base64.RawURLEncoding.DecodeString(testCase.ExpectedNonce)
			require.NoError(t, err)

			nonce, err := DeriveNonce(recordSequenceNumber, inputKeyingMaterial, salt)
			require.NoError(t, err)

			assert.Equal(t, expectedNonce, nonce)
		})
	}
}

func TestDeriveContentEncryptionKey(t *testing.T) {
	// All values are Base64 URL-encoded, without padding
	testCases := []struct {
		Name                string
		InputKeyingMaterial string
		Salt                string
		ExpectedCEK         string
	}{
		{
			Name:                "RFC 8188 3.1",
			InputKeyingMaterial: "yqdlZ-tYemfogSmv7Ws5PQ",
			Salt:                "I1BsxtFttlv3u_Oo94xnmw",
			ExpectedCEK:         "_wniytB-ofscZDh4tbSjHw",
		},
		{
			Name:                "RFC 8188 3.2",
			InputKeyingMaterial: "BO3ZVPxUlnLORbVGMpbT1Q",
			Salt:                "uNCkWiNYzKTnBN9ji3-qWA",
			ExpectedCEK:         "u_eEOTjjVWUVrH82pQNwpw",
		},
		{
			Name:                "gauntface/simple-push-demo",
			InputKeyingMaterial: "b6zpwBJpyjx2c3Dq5QAYzgJZX-R59KpfBBNglKExK3I",
			Salt:                "eQAMnLABzEBYh7vIcdkjeA",
			ExpectedCEK:         "Co4iuaOxN5KtkbN0dBYZyg",
		},
		{
			Name:                "web-push-libs",
			InputKeyingMaterial: "cHUxzkyPrxX8LEizP12yr9ZCCkPAM-OXb5yW_iEvGPI",
			Salt:                "lFIj-_UML_iEnPfvHM03HA",
			ExpectedCEK:         "_m3Qkn8PeEz76P60bUsdxg",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			inputKeyingMaterial, err := base64.RawURLEncoding.DecodeString(testCase.InputKeyingMaterial)
			require.NoError(t, err)

			salt, err := base64.RawURLEncoding.DecodeString(testCase.Salt)
			require.NoError(t, err)

			expectedCEK, err := base64.RawURLEncoding.DecodeString(testCase.ExpectedCEK)
			require.NoError(t, err)

			cek, err := DeriveContentEncryptionKey(inputKeyingMaterial, salt)
			require.NoError(t, err)

			fmt.Println(base64.RawURLEncoding.EncodeToString(cek))

			assert.Equal(t, expectedCEK, cek)
		})
	}
}
