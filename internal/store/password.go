package store

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns a bcrypt hash of a plaintext password.
func HashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
}

// CheckPassword reports whether pw matches the stored bcrypt hash.
func CheckPassword(hash []byte, pw string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}

// SHA256Hex is the lowercase SHA-256 hex of s. locklyctl sends an account's
// password as this hex (mirroring the Lockly app), so an account's stored
// verifier is bcrypt over it.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// HashAccountPassword hashes a plaintext account password the way the
// locklyctl-facing /api/login expects to verify it: bcrypt(SHA256Hex(pw)).
func HashAccountPassword(plaintext string) ([]byte, error) {
	return HashPassword(SHA256Hex(plaintext))
}
