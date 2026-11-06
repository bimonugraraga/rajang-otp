package rajangotp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	maxDigits  = big.NewInt(int64(len(Digits)))
	maxCharset = big.NewInt(int64(len(Charset)))
)

// GenerateNumericOTP generates a cryptographically secure numeric OTP of the specified length.
func GenerateNumericOTP(length int) (string, error) {

	otp := strings.Builder{}
	otp.Grow(length)

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, maxDigits)
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		otp.WriteByte(Digits[n.Int64()])
	}

	return otp.String(), nil
}

// GenerateAlphanumericOTP generates a secure code using uppercase letters and digits.
func GenerateAlphanumericOTP(length int) (string, error) {

	otp := strings.Builder{}
	otp.Grow(length)

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, maxCharset)
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		otp.WriteByte(Charset[n.Int64()])
	}

	return otp.String(), nil
}

func hashOTP(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func hashOTPWithSalt(input, salt string) string {
	h := hmac.New(sha256.New, []byte(salt))
	h.Write([]byte(input))
	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

// SOTP validator
func (t *SOTP) validateSOTPStruct() error {
	if t.RedisClient == nil {
		return fmt.Errorf("Redis client is required")
	}
	if t.ID == "" {
		return fmt.Errorf("ID is required")
	}
	if t.Length <= 0 {
		t.Length = 6 // default length
	}
	if t.DurationInSeconds <= 0 {
		t.DurationInSeconds = 300 // default duration (5 minutes)
	}

	return nil
}

// Save OTP to Redis with timelimit (1 user can only have 1 OTP at a time, if they request another one, the previous one will be invalidated).
// Default length is 6, default duration is 300 seconds (5 minutes), default prefix is "sotp:<ID>".
// The OTP will be stored in Redis with a key format: <custom_prefix>:sotp:<ID>, if the custom prefix is not provided, it will default to "sotp:<ID>".
// The value will be the hashed OTP and the expiration time will be set to the duration specified in the SOTP struct.
// If salt is provided, the OTP will be hashed with the salt before saving to Redis using HMAC-SHA256. Otherwise, it will be hashed without salt.
func (t *SOTP) GenerateAndSaveSOTP(ctx context.Context) (string, error) {

	if ctx == nil {
		return "", fmt.Errorf("context is required")
	}
	// Validate the SOTP struct
	err := t.validateSOTPStruct()
	if err != nil {
		return "", err
	}

	// Generate OTP
	var otp string
	if t.IsAlphaNumeric {
		otp, err = GenerateAlphanumericOTP(t.Length)
		if err != nil {
			return "", err
		}
	} else {
		otp, err = GenerateNumericOTP(t.Length)
		if err != nil {
			return "", err
		}
	}

	// Hash the OTP before saving to Redis
	var hashedOTP string
	if t.Salt != "" {
		hashedOTP = hashOTPWithSalt(otp, t.Salt)
	} else {
		hashedOTP = hashOTP(otp)
	}
	// Generate Redis key
	redisKey := t.generateRedisKey()

	// Save the hashed OTP to Redis with expiration
	err = t.RedisClient.Set(ctx, redisKey, hashedOTP, time.Duration(t.DurationInSeconds)*time.Second).Err()
	if err != nil {
		return "", fmt.Errorf("failed to save OTP to Redis: %w", err)
	}
	return otp, nil
}

// ValidateSOTP validates the provided OTP against the stored hashed OTP in Redis.
// It returns true if the OTP is valid, false otherwise. If there's an error during the process, it will return an error.
// After successful validation, the OTP will be deleted from Redis to prevent reuse.
// If salt is provided, the input OTP will be hashed with the salt before comparing with the stored hashed OTP using HMAC-SHA256. Otherwise, it will be hashed without salt.
func (t *SOTP) ValidateSOTP(ctx context.Context, inputOTP string) (bool, error) {

	if ctx == nil {
		return false, fmt.Errorf("context is required")
	}

	// Validate the SOTP struct
	err := t.validateSOTPStruct()
	if err != nil {
		return false, err
	}

	// hash the input OTP
	var hashedInputOTP string
	if t.Salt != "" {
		hashedInputOTP = hashOTPWithSalt(inputOTP, t.Salt)
	} else {
		hashedInputOTP = hashOTP(inputOTP)
	}

	// Generate Redis key
	redisKey := t.generateRedisKey()

	// Retrieve the hashed OTP from Redis
	storedHashedOTP, err := t.RedisClient.Get(ctx, redisKey).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, fmt.Errorf("failed to retrieve OTP from Redis: %w", err)
	}

	if hmac.Equal([]byte(hashedInputOTP), []byte(storedHashedOTP)) {
		// Delete the OTP from Redis after successful validation to prevent reuse
		err = t.RedisClient.Del(ctx, redisKey).Err()
		if err != nil {
			return false, fmt.Errorf("failed to delete OTP from Redis after validation: %w", err)
		}
		return true, nil
	}

	return false, nil
}

func (t *SOTP) generateRedisKey() string {
	if t.CustomPrefix != "" {
		return fmt.Sprintf("%s:%s%s", t.CustomPrefix, SOTPRedisKeyPrefix, t.ID)
	}
	return fmt.Sprintf("%s%s", SOTPRedisKeyPrefix, t.ID)
}

func (c *COTP) validateCOTPStruct() error {
	if c.RedisClient == nil {
		return fmt.Errorf("Redis client is required")
	}
	if c.ID == "" {
		return fmt.Errorf("ID is required")
	}
	if c.Length <= 0 {
		c.Length = 6 // default length
	}
	if c.DurationInSeconds <= 0 {
		c.DurationInSeconds = 300 // default duration (5 minutes)
	}
	if c.MaxConcurrentOTPs < 0 {
		return fmt.Errorf("MaxConcurrentOTPs cannot be negative")
	}
	return nil
}

// COTP allowed 1 user to have multiple concurrent OTPs, but each OTP will have a unique key in Redis based on the ID and a unique identifier (unix timestamp).
// Default length is 6, default duration is 300 seconds (5 minutes), default prefix is "cotp:<ID>:<unix_timestamp_mili>".
// If MaxConcurrentOTPs is 0, means no limit. Otherwise, if the maximum number of concurrent OTPs is reached, the oldest OTP will be deleted to make room for the new one.
// The key format will be: <custom_prefix>:cotp:<ID>:<unix_timestamp_mili>, if custom prefix is provided. Otherwise, it will default to "cotp:<ID>:<unix_timestamp_mili>".
// The value will be the hashed OTP and the expiration time will be set to the duration specified in the COTP struct.
// Each OTP has different expiration time, and the maximum number of concurrent OTPs can be set in the COTP struct.
// Best use for scenarios where a user may need to generate multiple OTPs concurrently, such as for different sessions or devices. Or for high latency applications.
// If salt is provided, the OTP will be hashed with the salt before saving to Redis using HMAC-SHA256. Otherwise, it will be hashed without salt.
func (c *COTP) GenerateAndSaveCOTP(ctx context.Context) (string, error) {

	if ctx == nil {
		return "", fmt.Errorf("context is required")
	}

	// Validate the COTP struct
	err := c.validateCOTPStruct()
	if err != nil {
		return "", err
	}

	// Generate OTP
	var otp string
	if c.IsAlphaNumeric {
		otp, err = GenerateAlphanumericOTP(c.Length)
		if err != nil {
			return "", err
		}
	} else {
		otp, err = GenerateNumericOTP(c.Length)
		if err != nil {
			return "", err
		}
	}

	milli := time.Now().UnixMilli()
	generatedKey := c.generateRedisKey()
	redisKey := fmt.Sprintf("%s:%d", generatedKey, milli)

	// Hash the OTP before saving to Redis
	var hashedOTP string
	if c.Salt != "" {
		hashedOTP = hashOTPWithSalt(otp, c.Salt)
	} else {
		hashedOTP = hashOTP(otp)
	}

	// Insert first, then check the number of existing OTPs for the given ID. If the maximum number of concurrent OTPs is reached, delete the oldest OTP.
	// Save the hashed OTP to Redis with expiration
	err = c.RedisClient.Set(ctx, redisKey, hashedOTP, time.Duration(c.DurationInSeconds)*time.Second).Err()
	if err != nil {
		return "", fmt.Errorf("failed to save OTP to Redis: %w", err)
	}

	// If MaxConcurrentOTPs is set to 0, it means no limit
	if c.MaxConcurrentOTPs == 0 {
		return otp, nil
	}

	// Check the number of existing OTPs for the given ID
	existingKeys, err := c.getExistingRedisKeys(ctx, generatedKey)
	if err != nil {
		return "", err
	}

	// If maximum number not reached, return the generated OTP
	if len(existingKeys) <= c.MaxConcurrentOTPs {
		return otp, nil
	}

	// If maximum number reached, delete the oldest OTP
	oldestKey := c.deletedKey(existingKeys)
	if oldestKey != "" {
		err = c.RedisClient.Del(ctx, oldestKey).Err()
		if err != nil {
			return "", fmt.Errorf("failed to delete oldest OTP from Redis: %w", err)
		}
	}
	return otp, nil
}

// ValidateCOTP validates the provided OTP against the stored hashed OTPs in Redis for the given ID.
// It returns true if the OTP is valid, false otherwise. If there's an error during the process, it will return an error.
// After successful validation, all the OTPs that related to the ID will be deleted from Redis to prevent reuse.
func (c *COTP) ValidateCOTP(ctx context.Context, inputOTP string) (bool, error) {

	if ctx == nil {
		return false, fmt.Errorf("context is required")
	}

	// Validate the COTP struct
	err := c.validateCOTPStruct()
	if err != nil {
		return false, err
	}

	// Get all the keys for the given ID
	generatedKey := c.generateRedisKey()
	existingKeys, err := c.getExistingRedisKeys(ctx, generatedKey)
	if err != nil {
		return false, err
	}
	if len(existingKeys) == 0 {
		return false, nil // No OTPs found for the given ID
	}

	// Get values for all the keys
	values, err := c.RedisClient.MGet(ctx, existingKeys...).Result()
	if err != nil {
		return false, fmt.Errorf("failed to retrieve OTP values from Redis: %w", err)
	}

	// Hash the input OTP and compare with the stored hashed OTPs
	var hashedInputOTP string
	if c.Salt != "" {
		hashedInputOTP = hashOTPWithSalt(inputOTP, c.Salt)
	} else {
		hashedInputOTP = hashOTP(inputOTP)
	}

	// Validate the input OTP against the stored hashed OTPs
	isValid, err := c.validateMultipleOTPs(hashedInputOTP, values)
	if err != nil {
		return false, fmt.Errorf("failed to validate OTPs: %w", err)
	}
	if !isValid {
		return false, nil
	}

	// If valid, delete all the OTPs for the given ID to prevent reuse
	err = c.RedisClient.Del(ctx, existingKeys...).Err()
	if err != nil {
		return false, fmt.Errorf("failed to delete OTPs from Redis after validation: %w", err)
	}
	return true, nil
}

func (c *COTP) getExistingRedisKeys(ctx context.Context, generatedKey string) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	var existingKeys []string
	iter := c.RedisClient.Scan(ctx, 0, fmt.Sprintf("%s:*", generatedKey), 0).Iterator()
	for iter.Next(ctx) {
		existingKeys = append(existingKeys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan existing OTPs: %w", err)
	}
	return existingKeys, nil
}

func (c *COTP) deletedKey(keys []string) string {
	if len(keys) == 0 {
		return ""
	}

	var oldestKey string
	var oldestTS int64 = -1
	for _, key := range keys {
		idx := strings.LastIndex(key, ":")
		if idx == -1 || idx+1 >= len(key) {
			continue
		}
		ts, err := strconv.ParseInt(key[idx+1:], 10, 64)
		if err != nil {
			continue // Lewati jika bukan angka
		}

		if oldestTS == -1 || ts < oldestTS {
			oldestTS = ts
			oldestKey = key
		}
	}
	return oldestKey
}

func (c *COTP) generateRedisKey() string {
	if c.CustomPrefix != "" {
		return fmt.Sprintf("%s:%s%s", c.CustomPrefix, COTPRedisKeyPrefix, c.ID)
	}
	return fmt.Sprintf("%s%s", COTPRedisKeyPrefix, c.ID)
}

func (c *COTP) validateMultipleOTPs(target string, otps []interface{}) (bool, error) {
	isValid := false
	for _, otp := range otps {
		if otp == nil {
			continue // Skip if the OTP is nil (expired or deleted)
		}
		strOtp, ok := otp.(string)
		if !ok {
			continue // Skip if the OTP is not a string
		}
		if hmac.Equal([]byte(target), []byte(strOtp)) {
			isValid = true // Prevent timing leak by continuing to check all OTPs even after a match is found
		}
	}

	return isValid, nil
}
