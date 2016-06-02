package iron

import (
	"crypto/aes"
	"crypto/cipher"
)

// CipherFactory is a function that takes a key and iv and returns and
// encryption and decryption block mode.
type CipherFactory func(key, iv []byte) (encrypt cipher.BlockMode, decrypt cipher.BlockMode, err error)

var (
	// AES256 implements aes-256-cbc encryption.
	AES256 = CipherFactory(func(key, iv []byte) (cipher.BlockMode, cipher.BlockMode, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}

		return cipher.NewCBCEncrypter(block, iv), cipher.NewCBCDecrypter(block, iv), nil
	})
)
