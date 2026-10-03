package safetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	errInvalidToken  = errors.New("Invalid token")
	errTokenExpired  = errors.New("Token expired")
	errInvalidWindow = errors.New("Invalid time window")
)

type SafeToken struct {
	timeWindow map[string]int64
	key        []byte
}

type Config struct {
	TimeWindows map[string]int64
	Secret      string
}

func New(init Config) (*SafeToken, error) {
	if len(init.Secret) < 12 {
		return nil, errors.New("Please provide safetoken  secret and time window")
	}

	// Defensive copy so external mutation of init.TimeWindows can't change rules.
	timeWindow := make(map[string]int64, len(init.TimeWindows))
	for k, v := range init.TimeWindows {
		if v <= 0 {
			return nil, errors.New("Please provide safetoken  secret and time window")
		}
		timeWindow[k] = v
	}
	if len(timeWindow) == 0 {
		timeWindow["access"] = 3600000     // 1 hour (ms)
		timeWindow["refresh"] = 2592000000 // 30 days (ms)
	}

	return &SafeToken{
		timeWindow: timeWindow,
		key:        []byte(init.Secret),
	}, nil
}

func (s *SafeToken) Create(data map[string]any) (string, error) {
	if data == nil {
		data = make(map[string]any)
	}
	return createHmacSha256Signature(data, s.key, timestamp())
}

func (s *SafeToken) Verify(token string, timeWindowKeys ...string) (map[string]any, error) {
	timeWindowKey := "access"
	if len(timeWindowKeys) > 0 && timeWindowKeys[0] != "" {
		timeWindowKey = timeWindowKeys[0]
	}

	window, ok := s.timeWindow[timeWindowKey]
	if !ok {
		return nil, errInvalidWindow
	}

	return verifyToken(token, s.key, window)
}

func (s *SafeToken) Decode(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return nil, errInvalidToken
	}
	return decodePayload(parts[2])
}

func decodePayload(data string) (map[string]any, error) {
	decodedData, err := base64UrlDecode(data)
	if err != nil {
		return nil, errInvalidToken
	}
	var payload map[string]any
	if err := json.Unmarshal(decodedData, &payload); err != nil {
		return nil, errInvalidToken
	}
	return payload, nil
}

func createHmacSha256Signature(payload map[string]any, key []byte, t string) (string, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	tbuf := base64UrlEncode([]byte(t))
	dataToSign := base64UrlEncode(payloadBytes)

	h := hmac.New(sha256.New, key)
	h.Write([]byte(dataToSign + tbuf))

	signature := base64UrlEncode(h.Sum(nil))
	return t + "." + signature + "." + dataToSign, nil
}

func verifyToken(token string, key []byte, timeWindow int64) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	t, signature, data := parts[0], parts[1], parts[2]
	if signature == "" || data == "" || !isHex8(t) {
		return nil, errInvalidToken
	}

	if !isInTime(timeWindow, t) {
		return nil, errTokenExpired
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(data + base64UrlEncode([]byte(t))))
	expectedSignature := base64UrlEncode(h.Sum(nil))

	if !timingSafeEqual(signature, expectedSignature) {
		return nil, errInvalidToken
	}
	return decodePayload(data)
}

// isHex8 matches /^[0-9a-fA-F]{8}$/ without regexp overhead.
func isHex8(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isInTime(timeWindow int64, timeCreated string) bool {
	// timeWindow > 0 is guaranteed by New().
	timeCreatedParsed, err := strconv.ParseInt(timeCreated, 16, 64)
	if err != nil || timeCreatedParsed <= 0 {
		return false
	}

	diff := time.Now().UnixMilli() - timeCreatedParsed*1000

	// Protect against future-dated token timestamp exploit (allow up to 5s clock skew)
	if diff < -5000 {
		return false
	}
	return diff <= timeWindow
}

func timestamp() string {
	return fmt.Sprintf("%08x", uint32(time.Now().Unix()))
}

func timingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func base64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64UrlDecode(str string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		s := strings.ReplaceAll(str, "-", "+")
		s = strings.ReplaceAll(s, "_", "/")
		for len(s)%4 != 0 {
			s += "="
		}
		return base64.StdEncoding.DecodeString(s)
	}
	return data, nil
}
