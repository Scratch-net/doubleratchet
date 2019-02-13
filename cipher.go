package doubleratchet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

const (
	CIPHER_KEY_LEN = 32
	GCM_KEY_LEN    = 32
	GCM_NONCE_SIZE = 12
)

var KDF_CIPHER_INFO = []byte("VIRGIL_RATCHET_KDF_CIPHER_INFO\000")

func Encrypt(key, data []byte) ([]byte, error) {

	if len(key) != CIPHER_KEY_LEN {
		return nil, errors.New("invalid key length")
	}

	kdf := hkdf.New(sha512.New, key, nil, KDF_CIPHER_INFO)

	keyBuf := make([]byte, GCM_KEY_LEN+GCM_NONCE_SIZE)

	_, err := kdf.Read(keyBuf)
	if err != nil {
		return nil, err
	}

	ciph, err := aes.NewCipher(keyBuf[:GCM_KEY_LEN])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(ciph)
	return aead.Seal(nil, keyBuf[GCM_KEY_LEN:], data, nil), nil
}
