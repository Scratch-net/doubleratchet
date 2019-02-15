package doubleratchet

import (
	"crypto/hmac"
	"crypto/sha512"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

const (
	RATCHET_SHARED_KEY_LEN = 32
	CURVE25519_KEY_LEN     = 32
)

var (
	KDF_ROOT_INFO = []byte{
		0x56, 0x49, 0x52, 0x47, 0x49, 0x4c, 0x5f, 0x52,
		0x41, 0x54, 0x43, 0x48, 0x45, 0x54, 0x5f, 0x4b,
		0x44, 0x46, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f,
		0x49, 0x4e, 0x46, 0x4f,
	}
	KDF_CHAIN_INFO = []byte{
		0xc5, 0x64, 0x95, 0x24, 0x74, 0x94, 0xc5, 0xf5,
		0x24, 0x15, 0x44, 0x34, 0x84, 0x55, 0x45, 0xf4,
		0xb4, 0x44, 0x65, 0xf5, 0x24, 0x15, 0x44, 0x34,
		0x84, 0x55, 0x45, 0xf4, 0x94, 0xe4, 0x64,
	}
	MESSAGE_KEY_SEED = []byte{0x01}
	CHAIN_KEY_SEED   = []byte{0x02}
)

func DeriveInitialKeys(sharedKey []byte) (rootKey, chainKey []byte, err error) {
	if len(sharedKey) != (RATCHET_SHARED_KEY_LEN*3) && len(sharedKey) != (RATCHET_SHARED_KEY_LEN*4) {
		err = errors.New("invalid shared key length")
		return
	}

	buf := make([]byte, RATCHET_SHARED_KEY_LEN*2)
	kdf := hkdf.New(sha512.New, sharedKey, nil, KDF_ROOT_INFO)
	if _, err = kdf.Read(buf); err != nil {
		return
	}
	return buf[:RATCHET_SHARED_KEY_LEN], buf[RATCHET_SHARED_KEY_LEN:], nil
}

func CreateChainKey(rootKey, public, private []byte) (newRootKey, newChainKey []byte, err error) {

	if len(rootKey) != RATCHET_SHARED_KEY_LEN || len(public) != CURVE25519_KEY_LEN || len(private) != CURVE25519_KEY_LEN {
		err = errors.New("Invalid key length")
	}

	sharedSecret, err := calcSharedSecret(public, private)
	if err != nil {
		return
	}

	buf := make([]byte, RATCHET_SHARED_KEY_LEN*2)
	kdf := hkdf.New(sha512.New, sharedSecret, rootKey, KDF_CHAIN_INFO)
	if _, err = kdf.Read(buf); err != nil {
		return
	}

	return buf[:RATCHET_SHARED_KEY_LEN], buf[RATCHET_SHARED_KEY_LEN:], nil
}

func CreateMessageKey(chainKey []byte) ([]byte, error) {
	if len(chainKey) != RATCHET_SHARED_KEY_LEN {
		return nil, errors.New("invalid key length")
	}
	h := hmac.New(sha512.New, chainKey)
	if _, err := h.Write(MESSAGE_KEY_SEED); err != nil {
		return nil, err
	}
	mac := h.Sum(nil)
	return mac[:RATCHET_SHARED_KEY_LEN], nil
}

func AdvanceChainKey(chainKey []byte) ([]byte, error) {
	if len(chainKey) != RATCHET_SHARED_KEY_LEN {
		return nil, errors.New("invalid key length")
	}
	h := hmac.New(sha512.New, chainKey)
	if _, err := h.Write(CHAIN_KEY_SEED); err != nil {
		return nil, err
	}
	mac := h.Sum(nil)
	return mac[:RATCHET_SHARED_KEY_LEN], nil
}
