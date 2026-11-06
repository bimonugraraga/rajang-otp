package rajangotp

import (
	"github.com/redis/go-redis/v9"
)

type SOTP struct {
	RedisClient       *redis.Client `json:"redis_client"`
	ID                string        `json:"id"`
	Length            int           `json:"length"`
	IsAlphaNumeric    bool          `json:"is_alphanumeric"`
	DurationInSeconds int           `json:"duration_in_seconds"`
	CustomPrefix      string        `json:"custom_prefix"`
	Salt              string
}

type COTP struct {
	RedisClient       *redis.Client `json:"redis_client"`
	ID                string        `json:"id"`
	Length            int           `json:"length"`
	IsAlphaNumeric    bool          `json:"is_alphanumeric"`
	DurationInSeconds int           `json:"duration_in_seconds"`
	CustomPrefix      string        `json:"custom_prefix"`
	MaxConcurrentOTPs int           `json:"max_concurrent_otps"`
	Salt              string
}
