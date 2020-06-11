package otp

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseKeyURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		uri     string
		want    *KeyURI
		wantErr error
	}{
		{
			name:    "invalid uri scheme",
			uri:     "https://example.com",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "invalid otp type",
			uri:     "otpauth://xotp/test%40example.com?secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
			wantErr: ErrInvalidOTPType,
		},
		{
			name:    "invalid algorithm",
			uri:     "otpauth://totp/test%40example.com?secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx&algorithm=SHA2",
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name:    "empty seceret param",
			uri:     "otpauth://totp/Example%3Atest%40example.com",
			wantErr: ErrEmptySecret,
		},
		{
			name:    "empty counter param",
			uri:     "otpauth://hotp/Example%3Atest%40example.com?secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
			wantErr: ErrEmptyCounter,
		},
		{
			name: "without label issuer",
			uri:  "otpauth://totp/test%40example.com?secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
			want: &KeyURI{
				typ:       totpType,
				user:      "test@example.com",
				secret:    "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
				algorithm: "SHA1",
				digits:    6,
				period:    30,
			},
		},
		{
			name: "with all params for totp",
			uri:  "otpauth://totp/Example%3A%20test%40example.com?secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx&algorithm=SHA256&digits=8&period=15&issuer=Example",
			want: &KeyURI{
				typ:       totpType,
				user:      "test@example.com",
				secret:    "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
				algorithm: "SHA256",
				digits:    8,
				period:    15,
				issuer:    "Example",
			},
		},
		{
			name: "with all params for hotp",
			uri:  "otpauth://hotp/Example%3A%20test%40example.com?secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx&algorithm=SHA256&digits=8&counter=1&issuer=Example",
			want: &KeyURI{
				typ:       hotpType,
				user:      "test@example.com",
				secret:    "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
				algorithm: "SHA256",
				digits:    8,
				counter:   1,
				issuer:    "Example",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyURI(tt.uri)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Failed\nwant: %v\n got: %v", tt.wantErr, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Failed\nwant: %+v\n got: %+v", tt.want, got)
			}
		})
	}
}

func TestKeyURI_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		k    *KeyURI
		want string
	}{
		{
			name: "totp",
			k: &KeyURI{
				typ:       totpType,
				user:      "test@example.com",
				secret:    "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
				algorithm: "SHA256",
				digits:    8,
				period:    15,
				issuer:    "Example",
			},
			want: "otpauth://totp/test%40example.com?algorithm=SHA256&digits=8&issuer=Example&period=15&secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
		},
		{
			name: "hotp",
			k: &KeyURI{
				typ:       hotpType,
				user:      "test@example.com",
				secret:    "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
				algorithm: "SHA256",
				digits:    8,
				counter:   1,
				issuer:    "Example",
			},
			want: "otpauth://hotp/test%40example.com?algorithm=SHA256&counter=1&digits=8&issuer=Example&secret=4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.k.String()
			if got != tt.want {
				t.Fatalf("Failed\nwant: %+v\n got: %+v", tt.want, got)
			}
		})
	}
}
