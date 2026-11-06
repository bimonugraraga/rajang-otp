package rajangotp_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	rajangotp "github.com/bimonugraraga/rajang-otp"
	"github.com/redis/go-redis/v9"
)

func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return mr, client
}

func TestGenerateOTP(t *testing.T) {
	t.Run("Numeric OTP length", func(t *testing.T) {
		code, err := rajangotp.GenerateNumericOTP(6)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("expected length 6, got %d", len(code))
		}
	})

	t.Run("Alphanumeric OTP length", func(t *testing.T) {
		code, err := rajangotp.GenerateAlphanumericOTP(8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(code) != 8 {
			t.Errorf("expected length 8, got %d", len(code))
		}
	})
}

func TestSOTP_Flow(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	ctx := context.Background()

	sotp := &rajangotp.SOTP{
		RedisClient:       client,
		ID:                "user-test-1",
		Length:            6,
		DurationInSeconds: 60,
		Salt:              "secret-key",
	}

	// 1. Generate & Save
	code, err := sotp.GenerateAndSaveSOTP(ctx)
	if err != nil {
		t.Fatalf("failed to generate and save SOTP: %v", err)
	}

	// 2. Validasi dengan kode yang salah
	valid, err := sotp.ValidateSOTP(ctx, "000000")
	if err != nil {
		t.Fatalf("unexpected error on wrong OTP: %v", err)
	}
	if valid {
		t.Errorf("expected false for invalid OTP, got true")
	}

	// 3. Validasi dengan kode yang benar
	valid, err = sotp.ValidateSOTP(ctx, code)
	if err != nil {
		t.Fatalf("unexpected error on valid OTP: %v", err)
	}
	if !valid {
		t.Errorf("expected true for valid OTP, got false")
	}

	// 4. Pastikan OTP langsung terhapus (tidak bisa reuse)
	valid, err = sotp.ValidateSOTP(ctx, code)
	if err != nil {
		t.Fatalf("unexpected error on reused OTP: %v", err)
	}
	if valid {
		t.Errorf("expected false for reused OTP, got true")
	}
}

func TestCOTP_MaxLimit(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	ctx := context.Background()

	cotp := &rajangotp.COTP{
		RedisClient:       client,
		ID:                "user-concurrent",
		Length:            6,
		DurationInSeconds: 60,
		MaxConcurrentOTPs: 2, // Maksimal hanya 2
		Salt:              "secret-key",
	}

	// Generate OTP 1
	code1, err := cotp.GenerateAndSaveCOTP(ctx)
	if err != nil {
		t.Fatalf("failed OTP 1: %v", err)
	}
	time.Sleep(2 * time.Millisecond) // Jeda sedikit agar millisecond timestamp beda

	// Generate OTP 2
	code2, err := cotp.GenerateAndSaveCOTP(ctx)
	if err != nil {
		t.Fatalf("failed OTP 2: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	// Generate OTP 3 (Harus mendepak OTP 1 karena limit = 2)
	code3, err := cotp.GenerateAndSaveCOTP(ctx)
	if err != nil {
		t.Fatalf("failed OTP 3: %v", err)
	}

	// Cek OTP 1: Harus sudah hangus
	valid1, err := cotp.ValidateCOTP(ctx, code1)
	if err != nil {
		t.Fatalf("error checking evicted OTP 1: %v", err)
	}
	if valid1 {
		t.Errorf("expected OTP 1 to be evicted, but it was still valid")
	}

	// Cek OTP 2: Masih valid, dan jika sukses, semua sisa OTP harus terhapus
	valid2, err := cotp.ValidateCOTP(ctx, code2)
	if err != nil {
		t.Fatalf("error checking valid OTP 2: %v", err)
	}
	if !valid2 {
		t.Errorf("expected OTP 2 to be valid")
	}

	// Cek OTP 3: Harus sudah ikut terhapus karena OTP 2 sudah sukses divalidasi (cleanup)
	valid3, err := cotp.ValidateCOTP(ctx, code3)
	if err != nil {
		t.Fatalf("error checking OTP 3 after cleanup: %v", err)
	}
	if valid3 {
		t.Errorf("expected OTP 3 to be deleted after OTP 2 validation success")
	}
}
