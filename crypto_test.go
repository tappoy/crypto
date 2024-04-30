package crypto

import (
	"testing"
)

var password = "test1234"

// test main
func TestMain(m *testing.M) {
	m.Run()
}

func TestCryptoNormal(t *testing.T) {
	c, err := NewCrypto(password)
	if err != nil {
		t.Error(err)
	}

	encrypted := c.Encrypt([]byte("hello"))
	if string(encrypted) == "hello" {
		t.Error("Error encrypt")
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Error(err)
	}

	if string(decrypted) != "hello" {
		t.Error("Error decrypt")
	}

	// wrong password
	c, err = NewCrypto("wrong")
	if err != nil {
		t.Error(err)
	}

	_, err = c.Decrypt(encrypted)
	if err == nil {
		t.Error("Error decrypt")
	}

}

func TestCryptoInvalidPasswordLength(t *testing.T) {
	_, err := NewCrypto("123456789012345678901234567890123")
	if err == nil {
		t.Error("Error invalid password length 33")
	}

	_, err = NewCrypto("")
	if err != nil {
		t.Error("Error invalid password length 0")
	}
}

func TestInvalidCiphertext(t *testing.T) {
	c, err := NewCrypto(password)
	if err != nil {
		t.Error(err)
	}

	_, err = c.Decrypt([]byte("hello"))
	if err != ErrInvalidCiphertext {
		t.Error("Error invalid ciphertext")
	}
}
