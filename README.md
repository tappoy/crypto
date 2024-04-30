# Package
`github.com/tappoy/crypto`

# About
This golang package provides some useful functions for encryption and decryption.

# Features

# Functions
- `NewCrypto(password string) *Crypto` - Create a new Crypto object.
- `Encrypt(bytes []byte) ([]byte, error)` - Encrypt a byte array.
- `Decrypt(bytes []byte) ([]byte, error)` - Decrypt a byte array.

# Errors
- `ErrCannotCreateCipher`: Cannot create the cipher.
- `ErrCannotCreateGcm`: Cannot create the GCM.
- `ErrCannotGenerateNonce`: Cannot generate the nonce.
- `ErrInvalidCiphertext`: The ciphertext is invalid.
- `ErrCannotDecryptSecret`: Cannot decrypt the secret.

# License
[LGPL-3.0](LICENSE)

# Author
[tappoy](https://github.com/tappoy)
