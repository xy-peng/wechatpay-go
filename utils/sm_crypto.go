package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/emmansun/gmsm/sm2"
)

// EncryptSM2WithPublicKey 使用公钥加密，输出 ASN.1 结果，符合 GB/T 32918.4-2016
func EncryptSM2WithPublicKey(pub *ecdsa.PublicKey, msg string) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("you should input *rsa.PublicKey")
	}
	ciphertext, err := sm2.EncryptASN1(rand.Reader, pub, []byte(msg))
	if err != nil {
		return "", fmt.Errorf("encrypt message with public key err:%s", err.Error())
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSM2WithPrivateKey 使用私钥解密，密文为 C1C3C2 格式，符合 GB/T 32918.4-2016
func DecryptSM2WithPrivateKey(priv *sm2.PrivateKey, ciphertext string) (string, error) {
	if priv == nil {
		return "", fmt.Errorf("you should input *rsa.PrivateKey")
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed, error=%s", err.Error())
	}

	plaintext, err := sm2.Decrypt(priv, data)
	if err != nil {
		return "", fmt.Errorf("decrypt ciphertext with private key err:%s", err.Error())
	}

	return string(plaintext), nil
}
