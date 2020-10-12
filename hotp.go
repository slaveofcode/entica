package entica

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"strconv"
	"strings"
)

type HOTP struct {
	OTP
	Counter    int
	byteSecret []byte
}

func NewHOTP(s string) *HOTP {
	return NewHOTPSHA(defaultDigit, sha1.New, s)
}

func NewHOTP256(s string) *HOTP {
	return NewHOTPSHA(defaultDigit, sha256.New, s)
}

func NewHOTP512(s string) *HOTP {
	return NewHOTPSHA(defaultDigit, sha512.New, s)
}

func NewHOTPSHA(digits int, hash func() hash.Hash, secret string) *HOTP {
	s := strings.ToUpper(secret)
	byteSecret, _ := base32.StdEncoding.DecodeString(s)
	return &HOTP{
		OTP: OTP{
			Hash:   hash,
			Digits: digits,
			Secret: s,
		},
		Counter:    1,
		byteSecret: byteSecret,
	}
}

func (h *HOTP) SetCounter(c int) {
	h.Counter = c
}

func (h *HOTP) Get() string {
	code := h.Current()
	h.Counter++
	return code
}

func (h *HOTP) toBytes(c int) []byte {
	bytes := make([]byte, 8)
	num, _ := strconv.ParseUint(strconv.Itoa(c), 0, 64)
	binary.BigEndian.PutUint64(bytes, num)
	return bytes
}

func (h *HOTP) AtCounter(c int) string {
	return h.genOTP(
		h.byteSecret,
		h.toBytes(c),
		h.Digits,
		h.Hash,
	)
}

func (h *HOTP) Current() string {
	return h.genOTP(
		h.byteSecret,
		h.toBytes(h.Counter),
		h.Digits,
		h.Hash,
	)
}

func (h *HOTP) Compare(code string) bool {
	return h.Get() == code
}
