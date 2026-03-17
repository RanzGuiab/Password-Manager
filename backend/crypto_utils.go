package main

import (
	// Encryption Modules
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

var masterKey = []byte("my_32_byte_master_key_for_aes_256!!") // Must be 32 bytes for AES-256

func encrypt(plainText string) (string, string, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, 12) // AES-GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	cipherText := aesgcm.Seal(nil, nonce, []byte(plainText), nil)
	return hex.EncodeToString(cipherText), hex.EncodeToString(nonce), nil
}

func decrypt(cipherTextHex string, nonceHex string) (string, error) {
	ciphertext, _ := hex.DecodeString(cipherTextHex)
	nonce, _ := hex.DecodeString(nonceHex)

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plainText, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
