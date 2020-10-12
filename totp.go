package entica

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"time"
)

const defaultDigit = 6

type TOTP struct {
	OTP
	byteSecret []byte
}

func NewTOTP(s string) *TOTP {
	return NewTOTPSHA(defaultDigit, sha1.New, s)
}

func NewTOTP256(s string) *TOTP {
	return NewTOTPSHA(defaultDigit, sha256.New, s)
}

func NewTOTP512(s string) *TOTP {
	return NewTOTPSHA(defaultDigit, sha512.New, s)
}

func NewTOTPSHA(digits int, hash func() hash.Hash, secret string) *TOTP {
	s := strings.ToUpper(secret)
	byteSecret, _ := base32.StdEncoding.DecodeString(s)
	return &TOTP{
		byteSecret: byteSecret,
		OTP: OTP{
			Hash:   hash,
			Digits: digits,
			Secret: s,
		},
	}
}

func (t *TOTP) make(unixTime int64) string {
	timeBegin := int64(0)
	timeSpan := int64(30)

	currTimeCycle := (unixTime - timeBegin) / timeSpan

	timeHex := strings.ToUpper(fmt.Sprintf("%x", currTimeCycle))

	// left padding with zero
	for x := len(timeHex); x < 16; x++ {
		timeHex = "0" + timeHex
	}

	// First 8 bytes are for the movingFactor
	// Compliant with base RFC 4226 (HOTP)
	for x := len(timeHex); x < 16; x++ {
		timeHex = "0" + timeHex
	}

	msgBytes, _ := hex.DecodeString(timeHex)

	return t.genOTP(t.byteSecret, msgBytes, t.Digits, t.Hash)
}

func (t *TOTP) Get() string {
	return t.make(time.Now().Unix())
}

func (t *TOTP) At(at time.Time) string {
	return t.make(at.Unix())
}

func (t *TOTP) Compare(code string) bool {
	return t.Get() == code
}
