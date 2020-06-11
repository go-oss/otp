package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-oss/otp"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	uri   = flag.String("uri", "", "Key uri (required)")
	watch = flag.Bool("watch", false, "If specified, display the token each time it expires.")
)

func main() {
	flag.Parse()
	if *uri == "" {
		fmt.Fprintln(os.Stderr, "uri flag is required")
		os.Exit(1)
	}

	totp, err := generateTOTP(*uri)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if err := displayToken(totp, *watch); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func generateTOTP(uri string) (*otp.TOTP, error) {
	o, err := otp.ParseKeyURI(uri)
	if err != nil {
		return nil, err
	}

	return otp.NewTOTP(o)
}

func displayToken(totp *otp.TOTP, watch bool) error {
	for {
		now := time.Now()
		token, err := totp.Generate(now)
		if err != nil {
			return err
		}

		if terminal.IsTerminal(int(os.Stdout.Fd())) {
			fmt.Fprintf(os.Stdout, "Token: %s\n\033[1A", token)
		} else {
			fmt.Println("Token:", token)
		}

		if !watch {
			return nil
		}
		<-time.After(totp.Expires(now).Sub(now) + time.Second)
	}
}
