# otp

TOTP, HOTP implementation in golang.

## Usage

### Package

```go
import "github.com/go-oss/otp"
```

### CLI

```
$ go install github.com/go-oss/otp/cmd/otp
```

```
$ otp -h
Usage of otp:
  -uri string
        Key uri (required)
  -watch
        If specified, display the token each time it expires.
```
