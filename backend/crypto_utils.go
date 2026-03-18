package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

var masterKey []byte

func initMasterKey() error {
	key := os.Getenv("MASTER_KEY")
	if len(key) != 32 {
		return fmt.Errorf("MASTER_KEY must be exactly 32 characters")
	}
	masterKey = []byte(key)
	return nil
}

func encrypt(plaintext string) (string, string, error) {
	if len(masterKey) == 0 {
		return "", "", fmt.Errorf("master key is not initialized")
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
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
	if len(masterKey) == 0 {
		return "", fmt.Errorf("master key is not initialized")
	}

	ciphertext, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext format")
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce format")
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(nonce) != aesgcm.NonceSize() {
		return "", fmt.Errorf("invalid nonce length")
	}

	plainText, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
