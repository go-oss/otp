package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"hash"
	"net/url"
	"strconv"
	"strings"
)

var (
	// ErrInvalidScheme is error that scheme is not "otpauth".
	ErrInvalidScheme = errors.New("invalid scheme")
	// ErrInvalidOTPType is error that specified otp type is not supported.
	ErrInvalidOTPType = errors.New("invalid otp type")
	// ErrEmptySecret is error that secret is empty.
	ErrEmptySecret = errors.New("secret param is required")
	// ErrInvalidAlgorithm is error that specified algorithm is not supported.
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	// ErrEmptyCounter is error that counter is empty.
	ErrEmptyCounter = errors.New("counter param is required for HOTP")
)

type otpType string

const (
	totpType otpType = "totp"
	hotpType otpType = "hotp"
)

func (t otpType) valid() bool {
	switch t {
	case totpType, hotpType:
		return true
	default:
		return false
	}
}

// KeyURI represents OTP configurations.
type KeyURI struct {
	typ       otpType
	user      string
	secret    string // key value encoded in base32
	algorithm string // SHA1 (default), SHA256 or SHA512
	digits    int    // 6 (default) or 8
	period    int    // 30 [sec] (default)
	counter   uint64
	issuer    string
}

func (k *KeyURI) hash() func() hash.Hash {
	switch k.algorithm {
	case "SHA1":
		return sha1.New
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return nil
	}
}

func (k *KeyURI) secretBytes() ([]byte, error) {
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	s, err := decoder.DecodeString(strings.ToUpper(k.secret))
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ParseKeyURI parses key uri formatted string.
// Key Uri Format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func ParseKeyURI(uri string) (*KeyURI, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "otpauth" {
		return nil, ErrInvalidScheme
	}
	otp := &KeyURI{
		typ:       otpType(u.Host),
		algorithm: "SHA1",
		digits:    6,
	}
	if !otp.typ.valid() {
		return nil, ErrInvalidOTPType
	}
	if otp.typ == totpType {
		otp.period = 30
	}
	if err := otp.parseUser(u.Path); err != nil {
		return nil, err
	}
	if err := otp.parseParams(u.Query()); err != nil {
		return nil, err
	}
	return otp, nil
}

func (k *KeyURI) parseUser(path string) error {
	p := strings.SplitN(strings.TrimPrefix(path, "/"), ":", 2)
	k.user = strings.TrimSpace(p[len(p)-1])
	return nil
}

func (k *KeyURI) parseParams(q url.Values) error {
	if v := q.Get("secret"); v != "" {
		k.secret = v
	} else {
		return ErrEmptySecret
	}
	if v := q.Get("algorithm"); v != "" {
		k.algorithm = v
		if k.hash() == nil {
			return ErrInvalidAlgorithm
		}
	}
	if v := q.Get("issuer"); v != "" {
		k.issuer = v
	}
	if v := q.Get("digits"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		k.digits = n
	}

	switch k.typ {
	case totpType:
		if v := q.Get("period"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return err
			}
			k.period = n
		}

	case hotpType:
		if v := q.Get("counter"); v != "" {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return err
			}
			k.counter = n
		} else {
			return ErrEmptyCounter
		}
	}

	return nil
}

// String encodes to key uri formatted string.
func (k *KeyURI) String() string {
	uri := &url.URL{
		Scheme:  "otpauth",
		Host:    string(k.typ),
		Path:    k.user,
		RawPath: url.QueryEscape(k.user), // use query escaped path
	}
	v := &url.Values{}
	v.Set("secret", k.secret)
	v.Set("algorithm", k.algorithm)
	v.Set("digits", strconv.Itoa(k.digits))
	switch k.typ {
	case totpType:
		v.Set("period", strconv.Itoa(k.period))
	case hotpType:
		v.Set("counter", strconv.FormatUint(k.counter, 10))
	}
	if k.issuer != "" {
		v.Set("issuer", k.issuer)
	}
	uri.RawQuery = v.Encode()
	return uri.String()
}
