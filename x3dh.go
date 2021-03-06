package doubleratchet

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
)

func X3DHInit(identityPrivate, ephPrivate, recieverIdentityPublic, recieverLongTermPublic, recieverOneTimePublic []byte) ([]byte, error) {
	sharedSecret := make([]byte, 0, 32*4)
	res, err := calcSharedSecret(recieverLongTermPublic, identityPrivate)
	if err != nil {
		return nil, err
	}
	sharedSecret = append(sharedSecret, res...)
	res, err = calcSharedSecret(recieverIdentityPublic, ephPrivate)
	if err != nil {
		return nil, err
	}
	sharedSecret = append(sharedSecret, res...)
	res, err = calcSharedSecret(recieverLongTermPublic, ephPrivate)
	if err != nil {
		return nil, err
	}
	sharedSecret = append(sharedSecret, res...)
	res, err = calcSharedSecret(recieverOneTimePublic, ephPrivate)
	if err == nil {
		sharedSecret = append(sharedSecret, res...)
	}

	return sharedSecret, nil
}

func X3DHRespond(senderIdentityPublic, senderEphemeralPublic, receiverIdentityPrivate, receiverLogTermPrivate, receiverOneTimePrivate []byte) ([]byte, error) {
	sharedSecret := make([]byte, 0, 32*4)
	res, err := calcSharedSecret(senderIdentityPublic, receiverLogTermPrivate)
	if err != nil {
		return nil, err
	}
	sharedSecret = append(sharedSecret, res...)
	res, err = calcSharedSecret(senderEphemeralPublic, receiverIdentityPrivate)
	if err != nil {
		return nil, err
	}
	sharedSecret = append(sharedSecret, res...)
	res, err = calcSharedSecret(senderEphemeralPublic, receiverLogTermPrivate)
	if err != nil {
		return nil, err
	}
	sharedSecret = append(sharedSecret, res...)
	res, err = calcSharedSecret(senderEphemeralPublic, receiverOneTimePrivate)
	if err == nil {
		sharedSecret = append(sharedSecret, res...)
	}
	return sharedSecret, nil
}

func calcSharedSecret(public, private []byte) ([]byte, error) {
	if len(public) != 32 || len(private) != 32 {
		return nil, errors.New("key size is invalid")
	}

	var sharedKey, pk, sk [32]byte
	copy(pk[:], public)
	copy(sk[:], private)

	curve25519.ScalarMult(&sharedKey, &sk, &pk)
	return sharedKey[:], nil
}
