package verifiers

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"github.com/emmansun/gmsm/sm2"
)

// SM2PublicKeyVerifier SM2 验签器，使用微信支付公钥
type SM2PublicKeyVerifier struct {
	keyID     string
	publicKey ecdsa.PublicKey
}

// Verify 使用微信支付提供的公钥验证签名
func (v *SM2PublicKeyVerifier) Verify(ctx context.Context, serialNumber, message, signature string) error {
	if ctx == nil {
		return fmt.Errorf("verify failed: context is nil")
	}
	if v.keyID != serialNumber {
		return fmt.Errorf("verify failed: key-id[%s] does not match serial number[%s]", v.keyID, serialNumber)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("verify failed: signature is not base64 encoded")
	}

	ok := sm2.VerifyASN1WithSM2(&v.publicKey, nil, []byte(message), sigBytes)
	if !ok {
		return fmt.Errorf("verify signature with public key error")
	}
	return nil
}

// NewSM2PublicKeyVerifier 初始化 SM2 微信支付公钥验签器
func NewSM2PublicKeyVerifier(keyID string, publicKey ecdsa.PublicKey) *SM2PublicKeyVerifier {
	return &SM2PublicKeyVerifier{keyID: keyID, publicKey: publicKey}
}
