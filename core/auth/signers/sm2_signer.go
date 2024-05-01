package signers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/emmansun/gmsm/sm2"
	"github.com/wechatpay-apiv3/wechatpay-go/core/auth"
	"strings"
)

type SM2Signer struct {
	MchID               string
	CertificateSerialNo string
	PrivateKey          *sm2.PrivateKey
}

func (s *SM2Signer) Sign(_ context.Context, message string) (*auth.SignatureResult, error) {
	if strings.TrimSpace(s.CertificateSerialNo) == "" {
		return nil, fmt.Errorf("you must set merchant's certificate serial-no to use SM2Signer")
	}

	sig, err := s.PrivateKey.Sign(rand.Reader, []byte(message), sm2.DefaultSM2SignerOpts)
	if err != nil {
		return nil, err
	}
	return &auth.SignatureResult{
		MchID:               s.MchID,
		CertificateSerialNo: s.CertificateSerialNo,
		Signature:           base64.StdEncoding.EncodeToString(sig),
	}, nil
}

func NewSM2Signer(mchID, certificateSerialNo string, privateKey *sm2.PrivateKey) *SM2Signer {
	return &SM2Signer{
		MchID:               mchID,
		CertificateSerialNo: certificateSerialNo,
		PrivateKey:          privateKey,
	}
}

func (s *SM2Signer) Algorithm() string {
	return "SM2-WITH-SM3"
}
