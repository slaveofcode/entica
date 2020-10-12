# Entica
Dead simple Golang OTP (One Time Password) library for both HOTP and TOTP without any dependency following both official [RFC6238](https://tools.ietf.org/html/rfc6238) and [RFC4226](https://tools.ietf.org/html/rfc4226) rules on the implementation.

## TOTP
A time-based OTP, using the time for the message validation.

```go
secret := entica.RandSecret() // base32 string (A-Z and 2-7) with length of 32 chars
totp := entica.NewTOTP(secret) // new default totp (sha1) with 6 digit result
totp.Get() // 918399

// or with more specific

secret := "IDI5FG3XTZE26AONPVRIVQP4DN2DV54J"
totp := entica.NewTOTPSHA(7, sha512.New, secret)
totp.Get() // 9183993

totp.Compare("codeToCheck") // return valid status
totp.At(time.Now().Sub(time.Hour * 3)) // return code at specific time, 3 hours earlier
totp.CodeAtUnix(1646373) // return code at specific unix time
```

## HOTP
HMAC-Based OTP, using the counter value for the message validation.

```go
secret := entica.RandSecret("SomeSalt")
hotp := entica.HOTP{
    Hash: entica.Sha1,
    Digits: 6,
    Secret: secret,  // 32bit string secret
    Counter: 1,
}

// or

hotp := entica.NewDefaultHOTP(secret, counter)

hotp.Check("codeToCheck") // return code at current time
hotp.CodeAtCounter(10) // return code at specific counter value 
hotp.CurrCounter() // return counter value 
```

## LICENSE
MIT License

Copyright (c) 2020 Aditya Kresna

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
