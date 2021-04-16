package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
)

func aeadFromKey(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func decryptInternal(path string, gcm cipher.AEAD, ciphertext []byte) ([]byte, error) {
	// Capture the parts
	nonce := ciphertext[5 : 5+gcm.NonceSize()]
	raw := ciphertext[5+gcm.NonceSize():]
	out := make([]byte, 0, len(raw)-gcm.NonceSize())

	// Attempt to open
	switch ciphertext[4] {
	case vault.AESGCMVersion1:
		return gcm.Open(out, nonce, raw, nil)
	case vault.AESGCMVersion2:
		aad := []byte(nil)
		if path != "" {
			aad = []byte(path)
		}
		return gcm.Open(out, nonce, raw, aad)
	default:
		return nil, fmt.Errorf("version bytes mis-match")
	}
}
func decryptTarget(cipher []byte, key []byte, path string) ([]byte, error) {

	aeadKey, err := aeadFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("aeadFromKey: %s", err)

	}
	clear, err := decryptInternal(path, aeadKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %s", err)
	}

	log.Debugf("Clear=%s", spew.Sdump(clear))
	return clear, nil

}

func decryptWithKeyring(kr *Keyring, cipher []byte, path string) (clear []byte, err error) {

	term := binary.BigEndian.Uint32(cipher[:4])
	log.Debugf("Looking for term:%d", term)
	termKey, ok := kr.keys[term]
	if !ok || termKey == nil {
		return nil, fmt.Errorf("no term key found")
	}
	return decryptTarget(cipher, termKey.Value, path)
}
