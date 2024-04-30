# Package
`github.com/tappoy/crypto`

# About
This golang package provides some useful functions for encryption and decryption.

# Features

# Functions
- `NewCrypto(password string) (*Crypto, error)` - Create a new Crypto object.
- `Encrypt(bytes []byte) []byte` - Encrypt a byte array.
- `Decrypt(bytes []byte) ([]byte, error)` - Decrypt a byte array.

# Errors
- `ErrInvalidPasswordLength`: The password length is invalid. It must be 8 to 32 characters.
- `ErrInvalidCiphertext`: The ciphertext is invalid.
- `ErrCannotDecryptSecret`: Cannot decrypt the secret.

# License
[LGPL-3.0](LICENSE)

# Author
[tappoy](https://github.com/tappoy)
