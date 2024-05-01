// This package provides some useful functions for encryption and decryption.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	// The password length is invalid. It must be 8 to 32 characters.
	ErrInvalidPasswordLength = errors.New("ErrInvalidPasswordLength")

	// The ciphertext is invalid.
	ErrInvalidCiphertext = errors.New("ErrInvalidCiphertext")

	// Cannot decrypt the secret.
	ErrCannotDecryptSecret = errors.New("ErrCannotDecryptSecret")
)

// Crypto object.
type Crypto struct {
	gcm   cipher.AEAD
	nonce []byte
}

// get password filled with spaces to 32 characters
func getPassword32(password string) (string, error) {
	if len(password) > 32 || len(password) < 8 {
		return "", ErrInvalidPasswordLength
	}
	return fmt.Sprintf("%-32s", password), nil
}

// Create a new Crypto object.
//
//	Errors:
//	- ErrInvalidPasswordLength: The password length is invalid. It must be 8 to 32 characters.
func NewCrypto(password string) (*Crypto, error) {
	password32, err := getPassword32(password)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher([]byte(password32))

	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	return &Crypto{gcm: gcm, nonce: nonce}, nil
}

// Encrypt the data.
func (c *Crypto) Encrypt(data []byte) []byte {
	return c.gcm.Seal(c.nonce, c.nonce, data, nil)
}

// Decrypt the data.
//
//	Errors:
//	- ErrInvalidCiphertext: The ciphertext is invalid.
//	- ErrCannotDecryptSecret: Cannot decrypt the secret.
func (c *Crypto) Decrypt(data []byte) ([]byte, error) {
	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decrypted, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrCannotDecryptSecret
	}

	return decrypted, nil
}
