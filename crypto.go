package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Errors
var (
	ErrInvalidPasswordLength = errors.New("ErrInvalidPasswordLength")
	ErrInvalidCiphertext     = errors.New("ErrInvalidCiphertext")
	ErrCannotDecryptSecret   = errors.New("ErrCannotDecryptSecret")
)

type Crypto struct {
	gcm   cipher.AEAD
	nonce []byte
}

// get password filled with spaces to 32 characters
func getPassword32(password string) (string, error) {
	if len(password) >= 32 {
		return "", ErrInvalidPasswordLength
	}
	return fmt.Sprintf("%-32s", password), nil
}

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

func (c *Crypto) Encrypt(data []byte) []byte {
	return c.gcm.Seal(c.nonce, c.nonce, data, nil)
}

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
