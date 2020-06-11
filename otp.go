package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"time"
)

// NewHOTP returns a new HOTP generator.
func NewHOTP(uri *KeyURI) (*HOTP, error) {
	s, err := uri.secretBytes()
	if err != nil {
		return nil, err
	}
	p := &HOTP{
		secret:  s,
		hash:    uri.hash(),
		digits:  uri.digits,
		counter: uri.counter,
	}
	return p, nil
}

// HOTP represents HMAC-based One Time Password.
type HOTP struct {
	secret  []byte
	hash    func() hash.Hash
	digits  int
	counter uint64
}

// Generate returns HOTP token from count.
func (p *HOTP) Generate(count uint64) (string, error) {
	p.counter = count
	return p.generate(count)
}

// Next returns next HOTP token.
func (p *HOTP) Next() (string, error) {
	p.counter++
	return p.generate(p.counter)
}

func (p *HOTP) generate(cnt uint64) (string, error) {
	h := hmac.New(p.hash, p.secret)
	if _, err := h.Write(p.itob(cnt)); err != nil {
		return "", err
	}
	mac := h.Sum(nil)
	code := p.truncate(mac)
	return p.format(code), nil
}

func (p *HOTP) itob(cnt uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, cnt)
	return b
}

// cf. https://tools.ietf.org/html/rfc4226#section-5.4
func (p *HOTP) truncate(mac []byte) uint32 {
	offset := mac[len(mac)-1] & 0xf
	code := binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7FFFFFFF
	return code % uint32(math.Pow10(p.digits))
}

func (p *HOTP) format(code uint32) string {
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", p.digits), code)
}

// NewTOTP returns a new TOTP generator.
func NewTOTP(uri *KeyURI) (*TOTP, error) {
	hotp, err := NewHOTP(uri)
	if err != nil {
		return nil, err
	}
	p := &TOTP{
		hotp:   hotp,
		period: int64(uri.period),
	}
	return p, nil
}

// TOTP represents Time-based One Time Password.
type TOTP struct {
	hotp   *HOTP
	period int64
}

// Generate TOTP token from time.
func (p *TOTP) Generate(t time.Time) (string, error) {
	ts := t.Unix()
	return p.hotp.generate(uint64(ts / p.period))
}

// Expires returns next expiry time.
func (p *TOTP) Expires(t time.Time) time.Time {
	ts := t.Unix()
	exp := ts + p.period - ts%p.period
	return time.Unix(exp, 0)
}
