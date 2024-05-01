package utils

import (
	"crypto/cipher"
	"encoding/base64"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

func transformSM4Key(apiV3Key string) (key []byte) {
	digest := sm3.Sum([]byte(apiV3Key))
	return digest[:16]
}

// DecryptSM4GCM 使用 SM4 GCM 解密
func DecryptSM4GCM(apiV3Key, associatedData, nonce, ciphertext string) (plaintext string, err error) {
	key := transformSM4Key(apiV3Key)

	binCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	p, err := sm4gcm.Open(nil, []byte(nonce), binCiphertext, []byte(associatedData))
	if err != nil {
		return "", err
	}
	return string(p), nil
}
