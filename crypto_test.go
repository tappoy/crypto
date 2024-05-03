package crypto

import (
	"fmt"
	"io/ioutil"
	"strings"
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
		t.Fatal(err)
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
	c, err = NewCrypto("wrong password")
	if err != nil {
		t.Fatal(err)
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

	_, err = NewCrypto("12345678901234567890123456789012")
	if err != nil {
		t.Error("Error invalid password length 32")
	}

	_, err = NewCrypto("12345678")
	if err != nil {
		t.Error("Error invalid password length 8")
	}

	_, err = NewCrypto("1234567")
	if err == nil {
		t.Error("Error invalid password length 7")
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

func ExampleHash() {
	hash := Hash("hello")
	fmt.Println("hash:", hash)

	// Output:
	// hash: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
}

func TestGenerateRandomString(t *testing.T) {
	// We can't test random string, because it's random. No seed.
	// generate 10 times for sample
	for i := 0; i < 10; i++ {
		randomString := GenerateRandomString(32)
		fmt.Printf("randomString: '%s'\n", randomString)
	}
}

func TestStreamNormal(t *testing.T) {
	key := "test1234"

	crypto, err := NewCrypto(key)
	if err != nil {
		t.Fatal(err)
	}

	txt := "hello"
	var sb strings.Builder
	w, err := crypto.Writer(&sb)
	if err != nil {
		t.Fatal(err)
	}

	w.Write([]byte(txt))
	encrypted := sb.String()

	fmt.Printf("encrypted: %s -> %x\n", txt, encrypted)

	txtReader := strings.NewReader(encrypted)
	r, err := crypto.Reader(txtReader)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ioutil.ReadAll(r)
	if err != nil {
		t.Error(err)
	}

	if string(decrypted) != "hello" {
		t.Error("Error decrypted")
	}

	fmt.Printf("decrypted: %x -> %s\n", encrypted, decrypted)
}

type AlwaysErrorWriter struct{}

func (a *AlwaysErrorWriter) Write(p []byte) (n int, err error) {
	return 100, fmt.Errorf("Always error")
}

type AlwaysZeroWriter struct{}

func (a *AlwaysZeroWriter) Write(p []byte) (n int, err error) {
	return 0, nil
}

type AlwaysErrorReader struct{}

func (a *AlwaysErrorReader) Read(p []byte) (n int, err error) {
	return 100, fmt.Errorf("Always error")
}

type AlwaysZeroReader struct{}

func (a *AlwaysZeroReader) Read(p []byte) (n int, err error) {
	return 0, nil
}

func TestStreamError(t *testing.T) {
	key := "test1234"

	crypto, err := NewCrypto(key)
	if err != nil {
		t.Fatal(err)
	}

	alwaysErrorWriter := &AlwaysErrorWriter{}
	_, err = crypto.Writer(alwaysErrorWriter)

	if err == nil {
		t.Error("Error Writer")
	}

	alwaysErrorReader := &AlwaysErrorReader{}
	_, err = crypto.Reader(alwaysErrorReader)
	if err == nil {
		t.Error("Error Reader")
	}

	alwaysZeroWriter := &AlwaysZeroWriter{}
	_, err = crypto.Writer(alwaysZeroWriter)
	if err == nil {
		t.Error("Error Writer")
	}

	alwaysZeroReader := &AlwaysZeroReader{}
	_, err = crypto.Reader(alwaysZeroReader)
	if err == nil {
		t.Error("Error Reader")
	}

}
