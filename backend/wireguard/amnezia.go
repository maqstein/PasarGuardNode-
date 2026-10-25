package wireguard

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// headerProtectionMinPadding is the smallest S1–S4 that AmneziaWG accepts with header
// protection on: the padding doubles as the header cipher nonce.
const headerProtectionMinPadding = 12

// AmneziaConfig holds the AmneziaWG device settings of a core. Its keys match the
// panel's host AmneziaWG properties and the AmneziaWG UAPI. Settings the client and
// server must share (S1–S4, H1–H4, the header protection key) have to equal the
// values the panel puts in client configs.
type AmneziaConfig struct {
	Jc   *uint32 `json:"jc,omitempty"`
	Jmin *uint32 `json:"jmin,omitempty"`
	Jmax *uint32 `json:"jmax,omitempty"`

	S1 *uint16 `json:"s1,omitempty"`
	S2 *uint16 `json:"s2,omitempty"`
	S3 *uint16 `json:"s3,omitempty"`
	S4 *uint16 `json:"s4,omitempty"`

	H1 *AmneziaRange `json:"h1,omitempty"`
	H2 *AmneziaRange `json:"h2,omitempty"`
	H3 *AmneziaRange `json:"h3,omitempty"`
	H4 *AmneziaRange `json:"h4,omitempty"`

	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`

	// AmneziaWG 3.1 settings.
	HeaderProtectionKey    string         `json:"header_protection_key,omitempty"`
	ContentPaddingAddition *AmneziaRange  `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         *AmneziaRange  `json:"rekey_after_time,omitempty"`
	RekeyTimeout           *AmneziaRange  `json:"rekey_timeout,omitempty"`
	RejectAfterTime        *AmneziaRange  `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       *AmneziaRange  `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   *AmneziaRange  `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         *AmneziaSwitch `json:"random_trailers,omitempty"`
	DisableCookies         *AmneziaSwitch `json:"disable_cookies,omitempty"`
}

// AmneziaRange is an AmneziaWG value that is a number or an inclusive "lo-hi" range.
// JSON accepts a number, a "n" string or a "lo-hi" string.
type AmneziaRange struct {
	Lo, Hi uint32
}

func (r *AmneziaRange) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	var text string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
	} else {
		text = string(data)
	}

	parsed, err := ParseAmneziaRange(text)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

func (r AmneziaRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// ParseAmneziaRange parses "n" or "lo-hi" with lo <= hi, both unsigned 32-bit.
func ParseAmneziaRange(text string) (AmneziaRange, error) {
	text = strings.TrimSpace(text)
	loText, hiText, isRange := strings.Cut(text, "-")
	lo, err := strconv.ParseUint(strings.TrimSpace(loText), 10, 32)
	if err != nil {
		return AmneziaRange{}, fmt.Errorf("invalid range %q: want a number or \"min-max\"", text)
	}
	hi := lo
	if isRange {
		hi, err = strconv.ParseUint(strings.TrimSpace(hiText), 10, 32)
		if err != nil {
			return AmneziaRange{}, fmt.Errorf("invalid range %q: want a number or \"min-max\"", text)
		}
	}
	if lo > hi {
		return AmneziaRange{}, fmt.Errorf("invalid range %q: min exceeds max", text)
	}
	return AmneziaRange{Lo: uint32(lo), Hi: uint32(hi)}, nil
}

func (r AmneziaRange) String() string {
	if r.Lo == r.Hi {
		return strconv.FormatUint(uint64(r.Lo), 10)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

func (r *AmneziaRange) orDefault(value uint32) AmneziaRange {
	if r == nil {
		return AmneziaRange{Lo: value, Hi: value}
	}
	return *r
}

func (r AmneziaRange) overlaps(other AmneziaRange) bool {
	return r.Lo <= other.Hi && other.Lo <= r.Hi
}

// AmneziaSwitch is an on/off setting. JSON accepts true/false or "on"/"off".
type AmneziaSwitch bool

func (s *AmneziaSwitch) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch v := value.(type) {
	case bool:
		*s = AmneziaSwitch(v)
		return nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "on", "true", "1":
			*s = true
			return nil
		case "off", "false", "0":
			*s = false
			return nil
		}
	}
	return fmt.Errorf("invalid switch %s: want \"on\" or \"off\"", data)
}

func (s AmneziaSwitch) MarshalJSON() ([]byte, error) {
	if s {
		return []byte(`"on"`), nil
	}
	return []byte(`"off"`), nil
}

// Validate rejects settings the AmneziaWG device would refuse, so a bad core config fails
// with a clear error before the interface is touched.
func (a *AmneziaConfig) Validate() error {
	if a == nil {
		return nil
	}

	if a.Jmin != nil && a.Jmax != nil && *a.Jmin > *a.Jmax {
		return errors.New("amnezia: jmin must not exceed jmax")
	}

	// An unset header keeps the WireGuard message type (1–4), which a set header can collide with.
	headers := []struct {
		name  string
		value AmneziaRange
	}{
		{"h1", a.H1.orDefault(1)},
		{"h2", a.H2.orDefault(2)},
		{"h3", a.H3.orDefault(3)},
		{"h4", a.H4.orDefault(4)},
	}
	for i := range headers {
		for j := i + 1; j < len(headers); j++ {
			if headers[i].value.overlaps(headers[j].value) {
				return fmt.Errorf("amnezia: %s and %s must not overlap", headers[i].name, headers[j].name)
			}
		}
	}

	if a.HeaderProtectionKey != "" {
		if _, err := a.headerProtectionKeyHex(); err != nil {
			return err
		}
		paddings := []struct {
			name  string
			value *uint16
		}{{"s1", a.S1}, {"s2", a.S2}, {"s3", a.S3}, {"s4", a.S4}}
		for _, padding := range paddings {
			if padding.value == nil || *padding.value < headerProtectionMinPadding {
				return fmt.Errorf("amnezia: %s must be at least %d when header_protection_key is set", padding.name, headerProtectionMinPadding)
			}
		}
	}

	return nil
}

// headerProtectionKeyHex converts the base64 key, as the panel and awg genkey write it,
// to the hex form of the UAPI.
func (a *AmneziaConfig) headerProtectionKeyHex() (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.HeaderProtectionKey))
	if err != nil || len(key) != 32 {
		return "", errors.New("amnezia: header_protection_key must be a base64-encoded 32-byte key")
	}
	return hex.EncodeToString(key), nil
}

// uapiLines returns the device-level UAPI "key=value" lines. Unset settings are left out,
// so the device keeps its defaults, which are those of plain WireGuard.
func (a *AmneziaConfig) uapiLines() ([]string, error) {
	if a == nil {
		return nil, nil
	}

	var lines []string
	addUint := func(key string, value *uint32) {
		if value != nil {
			lines = append(lines, fmt.Sprintf("%s=%d", key, *value))
		}
	}
	addPadding := func(key string, value *uint16) {
		if value != nil {
			lines = append(lines, fmt.Sprintf("%s=%d", key, *value))
		}
	}
	addRange := func(key string, value *AmneziaRange) {
		if value != nil {
			lines = append(lines, key+"="+value.String())
		}
	}
	addString := func(key, value string) {
		if value != "" {
			lines = append(lines, key+"="+value)
		}
	}
	addSwitch := func(key string, value *AmneziaSwitch) {
		if value != nil {
			lines = append(lines, key+"="+strconv.FormatBool(bool(*value)))
		}
	}

	addUint("jc", a.Jc)
	addUint("jmin", a.Jmin)
	addUint("jmax", a.Jmax)
	addPadding("s1", a.S1)
	addPadding("s2", a.S2)
	addPadding("s3", a.S3)
	addPadding("s4", a.S4)
	addRange("h1", a.H1)
	addRange("h2", a.H2)
	addRange("h3", a.H3)
	addRange("h4", a.H4)
	addString("i1", a.I1)
	addString("i2", a.I2)
	addString("i3", a.I3)
	addString("i4", a.I4)
	addString("i5", a.I5)
	if a.HeaderProtectionKey != "" {
		key, err := a.headerProtectionKeyHex()
		if err != nil {
			return nil, err
		}
		lines = append(lines, "header_protection_key="+key)
	}
	addRange("content_padding_addition", a.ContentPaddingAddition)
	addRange("rekey_after_time", a.RekeyAfterTime)
	addRange("rekey_timeout", a.RekeyTimeout)
	addRange("reject_after_time", a.RejectAfterTime)
	addRange("keepalive_timeout", a.KeepaliveTimeout)
	addRange("max_handshake_attempts", a.MaxHandshakeAttempts)
	addSwitch("random_trailers", a.RandomTrailers)
	addSwitch("disable_cookies", a.DisableCookies)

	return lines, nil
}
