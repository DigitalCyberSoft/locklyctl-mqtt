// Package lockly ports the Lockly BLE/MQTT protocol primitives from locklyctl
// (Python) and LocklyHA so this server can build and read the same frames a
// lock expects. Every function here has a counterpart in locklyctl/protocol.py
// or locklyctl/features.py and is pinned to it by the vectors in the tests.
//
// The master code (mc) plus the device UUID (ID) are the lock's AES key: treat
// both as secrets. Nothing here logs them.
package lockly

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"strings"
)

// DeriveAESKey builds the 16-byte AES-128 key from the master code and device
// UUID (DataUtils.m86653h; locklyctl protocol.derive_aes_key). The UUID is
// 12 bytes (24 hex chars); mc is the decimal master code.
func DeriveAESKey(mc, uuid string) ([]byte, error) {
	uuidBytes, err := hex.DecodeString(uuid)
	if err != nil {
		return nil, fmt.Errorf("uuid not hex: %w", err)
	}
	if len(uuidBytes) < 12 {
		return nil, fmt.Errorf("uuid is %d bytes, need at least 12", len(uuidBytes))
	}
	// Each decimal digit of mc expands to one byte with a leading zero nibble:
	// "24860092" -> 02 04 08 06 00 00 09 02.
	mcBytes := make([]byte, len(mc))
	for i, c := range []byte(mc) {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("master code is not all digits")
		}
		mcBytes[i] = c - '0'
	}
	key := make([]byte, 16)
	for i := 0; i < len(mc); i++ {
		key[i] = uuidBytes[i%len(uuidBytes)] ^ mcBytes[i]
	}
	for i := 8; i < 12; i++ {
		key[i] = uuidBytes[i] ^ mcBytes[i-8]
	}
	for i := 12; i < 16; i++ {
		key[i] = uuidBytes[i-12]
	}
	return key, nil
}

// EncryptMasterCode XOR-encodes the master code's digit values with the UUID
// bytes and returns uppercase hex (HexUtils.m86806g; encrypt_master_code).
// This is the <enc_mc> field embedded in most command plaintexts.
func EncryptMasterCode(mc, uuid string) (string, error) {
	uuidBytes, err := hex.DecodeString(uuid)
	if err != nil {
		return "", fmt.Errorf("uuid not hex: %w", err)
	}
	if len(uuidBytes) == 0 {
		return "", fmt.Errorf("uuid empty")
	}
	out := make([]byte, len(mc))
	for i, c := range []byte(mc) {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("master code is not all digits")
		}
		out[i] = (c - '0') ^ uuidBytes[i%len(uuidBytes)]
	}
	return strings.ToUpper(hex.EncodeToString(out)), nil
}

var crc8LUT = [16]byte{0, 49, 98, 83, 196, 245, 166, 151, 185, 136, 219, 234, 125, 76, 31, 46}

// CRC8 is Lockly's non-standard CRC-8 over every frame byte except the CRC
// itself (CRC8Utils2.a; crc8_lockly).
func CRC8(data []byte) byte {
	var crc byte
	for _, b := range data {
		s4 := byte((uint16(crc)<<4)&0xFF) ^ crc8LUT[(crc>>4)^(b>>4)]
		crc = byte((uint16(s4)<<4)&0xFF) ^ crc8LUT[(s4>>4)^(b&0x0F)]
	}
	return crc
}

// BuildBLEFrame wraps a payload: magic A1B2C3D4, little-endian length (payload
// + 8), payload, type byte, CRC-8 (build_ble_frame).
func BuildBLEFrame(payload []byte, typeByte byte) []byte {
	total := len(payload) + 8
	frame := make([]byte, 0, total)
	frame = append(frame, 0xA1, 0xB2, 0xC3, 0xD4)
	frame = append(frame, byte(total%256), byte(total/256))
	frame = append(frame, payload...)
	frame = append(frame, typeByte)
	return append(frame, CRC8(frame))
}

// AssembleFields concatenates hex fields, left-padding each single-character
// field to two and skipping empty ones (HexUtils.m86802c; _assemble_fields).
// An empty field drops out entirely, which is how an absent nonce vanishes
// rather than becoming "00".
func AssembleFields(fields ...string) string {
	var b strings.Builder
	for _, f := range fields {
		switch {
		case f == "":
			continue
		case len(f) == 1:
			b.WriteByte('0')
			b.WriteString(f)
		default:
			b.WriteString(f)
		}
	}
	return b.String()
}

// EncryptTypeAES is the low nibble of the frame type for AES-128/ECB commands.
const EncryptTypeAES = 0x5

// AESWrap zero-pads the plaintext hex to a 16-byte boundary, AES-128/ECB
// encrypts it, and wraps it in a BLE frame whose type byte carries the
// zero-padding length in the high nibble (_aes_wrap). The result is uppercase
// hex.
func AESWrap(rawHex string, key []byte, encryptType byte) (string, error) {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("plaintext not hex: %w", err)
	}
	pad := (16 - len(raw)%16) % 16
	if pad != 0 {
		raw = append(raw, make([]byte, pad)...)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	enc := make([]byte, len(raw))
	for i := 0; i < len(raw); i += aes.BlockSize {
		block.Encrypt(enc[i:i+aes.BlockSize], raw[i:i+aes.BlockSize])
	}
	typeByte := byte((pad << 4) | int(encryptType&0xF))
	return strings.ToUpper(hex.EncodeToString(BuildBLEFrame(enc, typeByte))), nil
}

// DecryptAck returns the decrypted payload hex (uppercase) of an encrypted ACK
// frame, or ok=false for a short rejection frame or anything unparseable
// (features.decrypt_ack). ackHex is the whole wire frame as hex.
func DecryptAck(ackHex, mc, uuid string) (string, bool) {
	if len(ackHex) < 18 {
		return "", false
	}
	payload, err := hex.DecodeString(ackHex[16 : len(ackHex)-2])
	if err != nil || len(payload) == 0 || len(payload)%16 != 0 {
		return "", false
	}
	key, err := DeriveAESKey(mc, uuid)
	if err != nil {
		return "", false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	out := make([]byte, len(payload))
	for i := 0; i < len(payload); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], payload[i:i+aes.BlockSize])
	}
	return strings.ToUpper(hex.EncodeToString(out)), true
}

// ExpandDigits prepends "0" to each character ("980798" -> "090800070908";
// HexUtils.m86803d; _expand_digits).
func ExpandDigits(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, c := range []byte(value) {
		b.WriteByte('0')
		b.WriteByte(c)
	}
	return b.String()
}
