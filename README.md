# rajang-otp

Hi. This is a small package to generate OTP that may contain only numeric or alpha-numeric. You can either the full capabilities by using the storing and validating OTP using redis, or just utilize the OTP generator.

## Requirements

- Go 1.27.1 or later
- Redis for the `SOTP` and `COTP` storage and validation methods

## Install

```sh
go get github.com/bimonugraraga/rajang-otp
```

Import the package:

```go
import rajangotp "github.com/bimonugraraga/rajang-otp"
```

## Generate an OTP

The standalone generators use Go's cryptographic random source and do not require Redis:

```go
package main

import (
	"fmt"
	"log"

	rajangotp "github.com/bimonugraraga/rajang-otp"
)

func main() {
	numericOTP, err := rajangotp.GenerateNumericOTP(6)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Numeric OTP:", numericOTP)

	alphanumericOTP, err := rajangotp.GenerateAlphanumericOTP(6)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Alphanumeric OTP:", alphanumericOTP)
}
```

`GenerateNumericOTP(length)` returns a string of decimal digits. `GenerateAlphanumericOTP(length)` returns a string of uppercase letters and digits. Both functions return an error if secure random data cannot be read.

## Store and validate one active OTP

`SOTP` stores a single OTP per ID. Generating another OTP for that ID replaces the previous one. A successfully validated OTP is deleted and cannot be reused.

```go
package main

import (
	"context"
	"fmt"
	"log"

	rajangotp "github.com/bimonugraraga/rajang-otp"
	"github.com/redis/go-redis/v9"
)

func main() {
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer client.Close()

	otp := &rajangotp.SOTP{
		RedisClient:       client,
		ID:                "user-123",
		Length:            6,
		DurationInSeconds: 300,
		CustomPrefix:      "my-app",
		Salt:              "use-a-secret-from-configuration",
	}

	code, err := otp.GenerateAndSaveSOTP(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("OTP:", code)

	valid, err := otp.ValidateSOTP(code)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Valid:", valid)
}
```

If `Length` or `DurationInSeconds` is zero or negative, the package defaults to 6 characters and 300 seconds. Set `IsAlphaNumeric` to `true` to generate an alphanumeric code. `Salt` is optional; when set, the stored OTP is HMAC-SHA256 hashed with that salt.

## Allow multiple active OTPs

`COTP` or ConcurrentOTP allows multiple active OTPs for an ID. `COTP` is based on `SOTP`, best use for system architecture that allow a user has multiple device run concurrently or to mitigate failure due to high latency of sending OTP (e.g. email, sms, whatsapp). If `MaxConcurrentOTPs` is greater than zero, the oldest OTP is deleted when the limit is exceeded. A successful validation deletes all active OTPs for that ID.

```go
otp := &rajangotp.COTP{
	RedisClient:       client,
	ID:                "user-123",
	Length:            6,
	IsAlphaNumeric:    true,
	DurationInSeconds: 300,
	CustomPrefix:      "my-app",
	MaxConcurrentOTPs: 5,
	Salt:              "use-a-secret-from-configuration",
}

code, err := otp.GenerateAndSaveCOTP(ctx)
if err != nil {
	log.Fatal(err)
}

valid, err := otp.ValidateCOTP(code)
if err != nil {
	log.Fatal(err)
}
fmt.Println("Valid:", valid)
```

`MaxConcurrentOTPs` set to `0` means no limit. Negative values return an error. `COTP` also defaults to a length of 6 and a duration of 300 seconds when those fields are zero or negative.

## Redis key format

The package stores only a hash of each OTP in Redis. By default, keys use these formats:

- `sotp:<ID>` for `SOTP` or `<custom_prefix>:sotp:<ID>` if `custom_prefix` is provided
- `cotp:<ID>:<unix-milliseconds>` for `COTP` or `<custom_prefix>:cotp:<ID>:<unix-milliseconds>` if `custom_prefix` is provided

When `CustomPrefix` is set, it is prepended, for example `my-app:sotp:user-123`. The configured duration is also used as the Redis key expiration.

## Setup Code
```go
package main

import (
	"context"
	"fmt"
	"time"

	rajangotp "github.com/bimonugraraga/rajang-otp"
	"github.com/redis/go-redis/v9"
)

func main() {
	// Generate Numeric OTP
	otp, err := rajangotp.GenerateNumericOTP(6)
	if err != nil {
		panic(err)
	}
	fmt.Println("Generate Numeric OTP:", otp)

	// Generate Alphanumeric OTP
	otp, err = rajangotp.GenerateAlphanumericOTP(6)
	if err != nil {
		panic(err)
	}
	fmt.Println("Generate Alphanumeric OTP:", otp)

	// Prepare Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	fmt.Println("--------------------------------------------------")
	fmt.Println("Generate and Validate SOTP with Redis")
	// Generate and Validate SOTP
	sotpStruct := &rajangotp.SOTP{
		RedisClient:       rdb,
		ID:                "test",
		Length:            6,
		IsAlphaNumeric:    true,
		DurationInSeconds: 300,
		CustomPrefix:      "rajang-otp",
		Salt:              "rajang",
	}
	ctx := context.Background()
	otp, err = sotpStruct.GenerateAndSaveSOTP(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("SOTP:", otp)
	time.Sleep(2 * time.Second) // Wait for 2 seconds before validating

	// Validate SOTP
	sotpStruct2 := &rajangotp.SOTP{
		RedisClient:  rdb,
		ID:           "test",
		CustomPrefix: "rajang-otp",
		Salt:         "rajang",
	}
	isValid, err := sotpStruct2.ValidateSOTP(ctx, otp)
	if err != nil {
		panic(err)
	}
	fmt.Println("SOTP is valid:", isValid)
	time.Sleep(2 * time.Second) // Wait for 2 seconds before validating

	// Generate and Validate COTP
	fmt.Println("--------------------------------------------------")
	fmt.Println("Generate and Validate COTP with Redis")
	cotpStruct := &rajangotp.COTP{
		RedisClient:       rdb,
		ID:                "test",
		Length:            6,
		IsAlphaNumeric:    true,
		DurationInSeconds: 300,
		CustomPrefix:      "rajang-otp",
		MaxConcurrentOTPs: 5,
		Salt:              "rajang",
	}
	otp, err = cotpStruct.GenerateAndSaveCOTP(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("COTP:", otp)
	time.Sleep(2 * time.Second) // Wait for 2 seconds before validating

	//Validate COTP
	cotpStruct2 := &rajangotp.COTP{
		RedisClient:  rdb,
		ID:           "test",
		CustomPrefix: "rajang-otp",
		Salt:         "rajang",
	}
	isValid, err = cotpStruct2.ValidateCOTP(ctx, otp)
	if err != nil {
		panic(err)
	}
	fmt.Println("COTP is valid:", isValid)
}

```