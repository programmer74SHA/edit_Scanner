package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Test Environment Only
const (
	encryptionKey = "MvRWOYx7KUpnA6w8QTnzJfLS2ED9CbGH" // 32 bytes for AES-256
	pepper        = "DF4Cgl9pT3zXbvN"
)

// EncryptPassword takes a plaintext password and returns an encrypted, base64-encoded string
func EncryptPassword(plaintext string) (string, error) {
	// Add pepper to the plaintext
	plaintextWithPepper := plaintext + pepper

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %w", err)
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("could not create GCM: %w", err)
	}

	// Create a new nonce (Number used ONCE)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("could not create nonce: %w", err)
	}

	// Encrypt and seal the data
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintextWithPepper), nil)

	// Return base64 encoded string
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPassword takes a base64-encoded encrypted string and returns the original plaintext
func DecryptPassword(encryptedBase64 string) (string, error) {
	// Decode the base64 string
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", fmt.Errorf("could not decode base64 string: %w", err)
	}

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %w", err)
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("could not create GCM: %w", err)
	}

	// Check if the ciphertext is long enough
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintextWithPepper, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("could not decrypt: %w", err)
	}

	// Remove the pepper
	plaintext := string(plaintextWithPepper[:len(plaintextWithPepper)-len(pepper)])

	return plaintext, nil
}
