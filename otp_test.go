package otp

import (
	"testing"
	"time"
)

func TestHOTP_Generate(t *testing.T) {
	t.Parallel()
	const secret = "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx"
	tests := []struct {
		name  string
		count uint64
		want  string
	}{
		{
			name:  "zero",
			count: 0,
			want:  "216994",
		},
		{
			name:  "next count",
			count: 1,
			want:  "873671",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hotp, err := NewHOTP(&KeyURI{
				typ:       hotpType,
				secret:    secret,
				algorithm: "SHA1",
				digits:    6,
				counter:   0,
			})
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			got, err := hotp.Generate(tt.count)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Failed\nwant: %v\n got: %v", tt.want, got)
			}
		})
	}
}

func TestHOTP_Next(t *testing.T) {
	t.Parallel()
	const secret = "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx"
	tests := []struct {
		name    string
		counter uint64
		want    string
	}{
		{
			name:    "zero",
			counter: 0,
			want:    "873671",
		},
		{
			name:    "next count",
			counter: 1,
			want:    "539540",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hotp, err := NewHOTP(&KeyURI{
				typ:       hotpType,
				secret:    secret,
				algorithm: "SHA1",
				digits:    6,
				counter:   tt.counter,
			})
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			got, err := hotp.Next()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Failed\nwant: %v\n got: %v", tt.want, got)
			}
		})
	}
}

func TestTOTP_Generate(t *testing.T) {
	t.Parallel()
	const secret = "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx"
	tests := []struct {
		name string
		time time.Time
		want string
	}{
		{
			name: "zero time",
			time: time.Unix(0, 0),
			want: "216994",
		},
		{
			name: "next period",
			time: time.Unix(31, 0),
			want: "873671",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totp, err := NewTOTP(&KeyURI{
				typ:       totpType,
				secret:    secret,
				algorithm: "SHA1",
				digits:    6,
				period:    30,
			})
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			got, err := totp.Generate(tt.time)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Failed\nwant: %v\n got: %v", tt.want, got)
			}
		})
	}
}

func TestTOTP_Expires(t *testing.T) {
	t.Parallel()
	const secret = "4ezxc3dfa4y645bdxbdebbzzb733xdwfzda56zdda5fd4zcdaczx"
	tests := []struct {
		name string
		time time.Time
		want time.Time
	}{
		{
			name: "zero time",
			time: time.Unix(0, 0),
			want: time.Unix(30, 0),
		},
		{
			name: "next period",
			time: time.Unix(31, 0),
			want: time.Unix(60, 0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totp, err := NewTOTP(&KeyURI{
				typ:       totpType,
				secret:    secret,
				algorithm: "SHA1",
				digits:    6,
				period:    30,
			})
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			got := totp.Expires(tt.time)
			if !got.Equal(tt.want) {
				t.Fatalf("Failed\nwant: %v\n got: %v", tt.want, got)
			}
		})
	}
}
