// This package provides simple functions related to cryptography.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"archive/tar"
	"compress/gzip"
	"path/filepath"
)

var (
	// The password length is invalid. It must be 8 to 32 characters.
	ErrInvalidPasswordLength = errors.New("ErrInvalidPasswordLength")

	// The ciphertext is invalid.
	ErrInvalidCiphertext = errors.New("ErrInvalidCiphertext")

	// Cannot decrypt the secret.
	ErrCannotDecryptSecret = errors.New("ErrCannotDecryptSecret")

	// Error about initialization vector.
	ErrInitializationVector = errors.New("ErrInitializationVector")
)

// Crypto object.
type Crypto struct {
	block cipher.Block
	gcm   cipher.AEAD
	nonce []byte
	iv    []byte
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
// Errors:
//   - ErrInvalidPasswordLength
func NewCrypto(password string) (*Crypto, error) {
	password32, err := getPassword32(password)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher([]byte(password32))

	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)

	return &Crypto{block: block, gcm: gcm, nonce: nonce, iv: iv}, nil
}

// Encrypt the data.
func (c *Crypto) Encrypt(data []byte) []byte {
	return c.gcm.Seal(c.nonce, c.nonce, data, nil)
}

// Decrypt the data.
//
// Errors:
//   - ErrInvalidCiphertext
//   - ErrCannotDecryptSecret
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

// Hash is a function to hash the given string. (SHA-256)
//
//	ex) "hello" -> "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
func Hash(s string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

// Md5 is a function to hash the given string. (MD5)
func Md5(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

// all printable ascii characters
var asciiPrintable = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")

// Generate a random string with the given length.
func GenerateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	for i := 0; i < length; i++ {
		b[i] = asciiPrintable[int(b[i])%len(asciiPrintable)]
	}
	return string(b)
}

// Make cipher stream writer.
//
// Errors:
//   - ErrInitializationVector
func (c *Crypto) Writer(w io.Writer) (io.Writer, error) {
	n, err := w.Write(c.iv)
	if err != nil || n != len(c.iv) {
		return nil, ErrInitializationVector
	}

	stream := cipher.NewOFB(c.block, c.iv)
	return &cipher.StreamWriter{S: stream, W: w}, nil
}

// Make cipher stream reader.
//
// Errors:
//   - ErrInitializationVector
func (c *Crypto) Reader(r io.Reader) (io.Reader, error) {
	iv := make([]byte, aes.BlockSize)
	n, err := r.Read(iv)
	if err != nil || n != len(iv) {
		return nil, ErrInitializationVector
	}

	stream := cipher.NewOFB(c.block, iv)
	return &cipher.StreamReader{S: stream, R: r}, nil
}

// GzEncrypto is a function to gzip and encrypt the data from r to w with the given password.
//
// Errors:
//   - ErrInvalidPasswordLength
//   - ErrInitializationVector
//   - any errors from io.Copy, gzip.NewWriterLevel
func GzEncrypto(r io.Reader, w io.Writer, password string) error {
	// cipher
	c, err := NewCrypto(password)
	if err != nil {
		return err
	}

	cw, err := c.Writer(w)
	if err != nil {
		return err
	}

	// gz
	gz, err := gzip.NewWriterLevel(cw, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer gz.Close()

	_, err = io.Copy(gz, r)
	return err
}

// DecryptoGunzip is a function to decrypt and gunzip the data from r to w with the given password.
//
// Errors:
//   - ErrInvalidPasswordLength
//   - ErrInitializationVector
//   - any errors from io.Copy
func DecryptoGunzip(r io.Reader, w io.Writer, password string) error {
	// cipher
	c, err := NewCrypto(password)
	if err != nil {
		return err
	}
	cr, err := c.Reader(r)
	if err != nil {
		return err
	}

	// gz
	gz, err := gzip.NewReader(cr)
	if err != nil {
		return err
	}
	defer gz.Close()

	_, err = io.Copy(w, gz)
	return err
}

// TarGzEncrypto is a function to tar, gzip, and encrypt the given directory.
//
// Errors:
//   - ErrInvalidPasswordLength
//   - ErrInitializationVector
//   - any errors from io.Copy, gzip.NewWriterLevel, filepath.Walk, tar.FileInfoHeader, tw.WriteHeader, os.Open
func TarGzEncrypto(src string, dst io.Writer, password string) error {
	// cipher
	c, err := NewCrypto(password)
	if err != nil {
		return err
	}

	cw, err := c.Writer(dst)
	if err != nil {
		return err
	}

	// gz
	gz, err := gzip.NewWriterLevel(cw, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.Mode().IsDir() {
			return nil
		}

		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}

		// check abs path
		if filepath.IsAbs(file) {
			// to relative path
			hdr.Name = file[1:]
		} else {
			hdr.Name = file
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		fr, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fr.Close()

		_, err = io.Copy(tw, fr)
		return err
	})
}

// DecryptoGunzipUntar is a function to decrypt, gunzip, and untar the given data.
//
// Errors:
//   - ErrInvalidPasswordLength
//   - ErrInitializationVector
//   - any errors from io.Copy, gzip.NewReader, tar.NewReader, os.MkdirAll, os.OpenFile, io.Copy
func DecryptoGunzipUntar(src io.Reader, dst string, password string) error {
	// cipher
	c, err := NewCrypto(password)
	if err != nil {
		return err
	}
	cr, err := c.Reader(src)
	if err != nil {
		return err
	}

	// gz
	gz, err := gzip.NewReader(cr)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		path := filepath.Join(dst, hdr.Name)
		if hdr.FileInfo().IsDir() {
			os.MkdirAll(path, hdr.FileInfo().Mode())
			continue
		}

		dir := filepath.Dir(path)
		os.MkdirAll(dir, 0755)

		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, hdr.FileInfo().Mode())
		if err != nil {
			return err
		}

		_, err = io.Copy(f, tr)
		if err != nil {
			return err
		}
		f.Close()
	}

	return nil
}
