package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

func Encrypt(key []byte, plaintext string) (ciphertext string, nonce string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonceBytes := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return "", "", err
	}

	encrypted := aesGCM.Seal(nil, nonceBytes, []byte(plaintext), nil)

	return hex.EncodeToString(encrypted), hex.EncodeToString(nonceBytes), nil
}

func Decrypt(key []byte, ciphertextHex string, nonceHex string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceBytes, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", err
	}

	ciphertextBytes, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	if len(nonceBytes) != aesGCM.NonceSize() {
		return "", errors.New("invalid nonce size")
	}

	plaintext, err := aesGCM.Open(nil, nonceBytes, ciphertextBytes, nil)
	if err != nil {
		return "", errors.New("decryption failed: authentication tag mismatch")
	}

	return string(plaintext), nil
}
