package entica

import (
	"crypto/hmac"
	"encoding/base32"
	"hash"
	"math"
	"strconv"

	"crypto/rand"
)

type Hash int

const (
	Sha1 Hash = iota + 1
	Sha256
	Sha512
)

type OTP struct {
	Hash   func() hash.Hash
	Digits int
	Secret string
}

func (otp *OTP) hmacSHA(crypto func() hash.Hash, msg, secret []byte) []byte {
	mac := hmac.New(crypto, secret)
	mac.Write(msg)
	return mac.Sum(nil)
}

func (otp *OTP) genOTP(secret []byte, msgBytes []byte, digits int, crypto func() hash.Hash) string {
	hashBytes := otp.hmacSHA(crypto, msgBytes, secret)

	// get the last byte and do bitwise and with 4 bits
	offset := hashBytes[len(hashBytes)-1] & 0xf

	firstPart := int32(hashBytes[offset] & 0x7f)
	secondPart := int32(hashBytes[offset+1] & 0xff)
	thirdPart := int32(hashBytes[offset+2] & 0xff)
	fourthPart := int32(hashBytes[offset+3] & 0xff)

	binary := firstPart<<24 |
		secondPart<<16 |
		thirdPart<<8 |
		fourthPart

	val := int(binary) % int(math.Pow10(digits))
	result := strconv.Itoa(val)
	for x := len(result); x < digits; x++ {
		result = "0" + result
	}

	return result
}

func getRandBytes(length int) []byte {
	byte256Key := make([]byte, length)
	_, err := rand.Read(byte256Key[:])

	if err != nil {
		panic("Unable to create random key")
	}

	return byte256Key
}

func RandSecret() string {
	randBytes := getRandBytes(20) // produce 32 chars random string
	return base32.StdEncoding.EncodeToString(randBytes)
}
