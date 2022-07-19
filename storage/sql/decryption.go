package sql

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"github.com/dexidp/dex/pkg/props"
	"io"
	"strings"
)

var T = props.Config()
var iv = "ACCESSINITVECTOR"
var secretKey = T.SecretKey

func decrypt(plainText string) (decryptedText string, err error) {
	key, _ := base64.StdEncoding.DecodeString(secretKey)
	ciphertext, _ := base64.StdEncoding.DecodeString(plainText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return decryptedText, fmt.Errorf("failed to created NewCipher: %v", err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return decryptedText, fmt.Errorf("NewGCMWithNonceSize: %v", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	r := strings.NewReader(iv)
	io.ReadFull(r, nonce)

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return decryptedText, fmt.Errorf("NewGCMWithNonceSize: %v", err)
	}

	decryptedText = string(plaintext)
	return decryptedText, nil
}
