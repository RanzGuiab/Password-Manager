package main

import (
	// Encryption Modules
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

var masterKey = []byte("a-very-secret-key-32-chars-long!")

func encrypt(plaintext string) (string, string, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		fmt.Printf("Cipher Error: %v\n", err) // This will tell us if the key is the wrong size
		return "", "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(nonce), nil
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
