package crypto

import (
	"fmt"
	"io/ioutil"
	"os"
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
	key := password

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
	key := password

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

func TestMd5(t *testing.T) {
	md5 := Md5("object strage test\n")
	if md5 != "c253efd685cdae53d5d49f2d1ce9b864" {
		t.Errorf("got: %s, want: c253efd685cdae53d5d49f2d1ce9b864", md5)
	}
}

func TestGzEncrypto(t *testing.T) {
	// rm tmp
	err := os.RemoveAll("tmp/test")
	if err != nil {
		t.Fatal(err)
	}

	// make dir
	err = os.MkdirAll("tmp/test", 0755)

	// make test text
	var testText []byte
	for i := 0; i < 100; i++ {
		testText = append(testText, []byte("hellohellohello\n")...)
	}

	// make a test file
	err = os.WriteFile("tmp/test/test.txt", testText, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// create destination file
	dest, err := os.Create("tmp/test/test.txt.gzc")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// open source file
	src, err := os.Open("tmp/test/test.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	// GzEncrypto
	err = GzEncrypto(src, dest, password)
	if err != nil {
		t.Error(err)
	}

	// DecryptGunzip
	dest, err = os.Create("tmp/test/test.txt.dec")
	if err != nil {
		t.Fatal(err)
	}

	src, err = os.Open("tmp/test/test.txt.gzc")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	err = DecryptoGunzip(src, dest, password)
	if err != nil {
		t.Error(err)
	}

	// Show the result
	destStr, err := os.ReadFile("tmp/test/test.txt.dec")
	if err != nil {
		t.Fatal(err)
	}

	// check the result
	if string(destStr) != string(testText) {
		t.Error("Error GzEncrypto")
	}

}

func TestTarGzCrypto(t *testing.T) {
	// rm tmp
	err := os.RemoveAll("tmp/test")
	if err != nil {
		t.Fatal(err)
	}

	// make dir
	err = os.MkdirAll("tmp/test/d1/d2", 0755)

	// make a test file
	err = os.WriteFile("tmp/test/d1/test.txt", []byte("test1"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile("tmp/test/d1/d1.txt", []byte("d1"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile("tmp/test/d1/d2/d2.txt", []byte("d2"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// create tar dst file
	destTar, err := os.Create("tmp/test/test.tgzc")

	// tar
	target := "tmp/test/d1"
	err = TarGzEncrypto(target, destTar, password)
	if err != nil {
		t.Error(err)
	}

	// untar
	destDir := "tmp/test/untar"
	err = os.MkdirAll(destDir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	srcTar, err := os.Open("tmp/test/test.tgzc")
	if err != nil {
		t.Fatal(err)
	}
	defer srcTar.Close()

	err = DecryptoGunzipUntar(srcTar, destDir, password)
	if err != nil {
		t.Error(err)
	}

	// check the result
	destStr, err := os.ReadFile("tmp/test/untar/tmp/test/d1/test.txt")
	if err != nil {
		t.Fatal(err)
	}

	if string(destStr) != "test1" {
		t.Error("Error TarGzCrypto")
	}
}
