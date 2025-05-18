package aes128gcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

func Encrypt(plaintext []byte, ikm []byte, salt []byte, keyID []byte, recordSize int) ([]byte, error) {
	// Valid records always contain at least a padding delimiter octet and a
	// 16-octet authentication tag. Additionally require 1B of data per record.
	if recordSize < 18 {
		return nil, fmt.Errorf("aes128gcm: invalid record size")
	}

	var header Header
	copy(header.Salt[:], salt)
	header.RecordSize = uint32(recordSize)
	header.KeyID = bytes.Clone(keyID)

	cek, err := DeriveContentEncryptionKey(ikm, header.Salt[:])
	if err != nil {
		return nil, err
	}

	// TODO: Should Encrypt take and return a reader instead, so that we don't
	// have to deal with allocating the entire ciphertext?
	// TODO: For Web Push, we only ever have a single record, unnecessary to do
	// this dance?

	// 16B AEAD tag, 1B padding delimiter per record, rest is data
	dataBytesPerRecord := recordSize - 17
	records := (len(plaintext) + dataBytesPerRecord - 1) / dataBytesPerRecord

	// TODO: Can we calculate the plaintext size beforehand and allocate it once?
	ciphertext := make([]byte, 0)

	ciphertext, err = header.AppendBinary(ciphertext)
	if err != nil {
		return nil, err
	}

	// TODO: Issue is dataBytesPerRecord includes padding, but we don't know how
	// much beforehand

	for record := 0; record < records; record++ {
		recordStart := record * dataBytesPerRecord
		recordEnd := min(len(plaintext), recordStart+(dataBytesPerRecord))

		padDelimiter := byte(0x01)
		if record == records-1 {
			padDelimiter = 0x02
		}

		data := make([]byte, recordEnd-recordStart+1)
		copy(data, plaintext[recordStart:recordEnd])
		data[recordEnd-recordStart] = padDelimiter

		var recordSequenceNumber [12]byte
		binary.BigEndian.PutUint64(recordSequenceNumber[4:], uint64(record))

		nonce, err := DeriveNonce(recordSequenceNumber[:], ikm, salt)
		if err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, err
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		data = aead.Seal(data[:0], nonce, data, nil)
		ciphertext = append(ciphertext, data...)
	}

	return ciphertext, nil
}

// TODO: Support uint96_max records rather than int_max in loops, record
// sequence number serialization (note that WebPush only ever uses a single
// record)
func Decrypt(ciphertext []byte, ikm []byte) ([]byte, error) {
	var header Header
	if err := header.UnmarshalBinary(ciphertext); err != nil {
		return nil, err
	}

	cek, err := DeriveContentEncryptionKey(ikm, header.Salt[:])
	if err != nil {
		return nil, err
	}

	// TODO: Should Decrypt take and return a reader instead, so that we don't
	// have to deal with allocating the entire plaintext?
	// TODO: For Web Push, we only ever have a single record, unnecessary to do
	// this dance?

	records := (len(ciphertext) - header.Length() + int(header.RecordSize) - 1) / int(header.RecordSize)

	// TODO: Can we calculate the plaintext size beforehand and allocate it once?
	// Optional padding in the last record makes it difficult?
	plaintext := make([]byte, 0)
	for record := 0; record < records; record++ {
		recordStart := record*int(header.RecordSize) + header.Length()
		if recordStart >= len(ciphertext) {
			break
		}

		recordEnd := min(len(ciphertext), recordStart+int(header.RecordSize))

		var recordSequenceNumber [12]byte
		binary.BigEndian.PutUint64(recordSequenceNumber[4:], uint64(record))

		nonce, err := DeriveNonce(recordSequenceNumber[:], ikm, header.Salt[:])
		if err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, err
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		// TODO: If we knew the size beforehand, we could write directly to the
		// ciphertext, instead of copying the part
		part, err := aead.Open(nil, nonce, ciphertext[recordStart:recordEnd], nil)
		if err != nil {
			return nil, err
		}

		paddingDelimiterIndex := 0
		for i := len(part) - 1; i > 0; i-- {
			if part[i] == 0x00 {
				// Padding
			} else {
				// Assumed padding delimiter
				paddingDelimiterIndex = i
				break
			}
		}

		// A decrypter MUST fail if the record contains no non-zero octet
		if paddingDelimiterIndex == 0 {
			return nil, fmt.Errorf("aes128gcm: invalid padding")
		}

		isLastRecord := record == records-1

		// A decrypter MUST fail if the last record contains a padding delimiter
		// with a value other than 2 or if any record other than the last contains a
		// padding delimiter with a value other than 1.
		paddingDelimiter := part[paddingDelimiterIndex]
		if isLastRecord && paddingDelimiter != 0x02 ||
			!isLastRecord && paddingDelimiter != 0x01 {
			return nil, fmt.Errorf("aes128gcm: invalid padding delimiter")
		}

		plaintext = append(plaintext, part[:paddingDelimiterIndex]...)
	}

	return plaintext, nil
}

func DeriveNonce(recordSequenceNumber []byte, inputKeyingMaterial []byte, salt []byte) ([]byte, error) {
	if len(recordSequenceNumber) != 12 {
		return nil, fmt.Errorf("aes128gcm: invalid sequence number length")
	}

	nonce, err := hkdf.Key(sha256.New, inputKeyingMaterial, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(nonce); i++ {
		nonce[i] ^= recordSequenceNumber[i]
	}

	return nonce, nil
}

func DeriveContentEncryptionKey(inputKeyingMaterial []byte, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, inputKeyingMaterial, salt, "Content-Encoding: aes128gcm\x00", 16)
}
