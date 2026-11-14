package store

import "golang.org/x/crypto/bcrypt"

// HashPassword returns a bcrypt hash of a plaintext password.
func HashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
}

// CheckPassword reports whether pw matches the stored bcrypt hash.
func CheckPassword(hash []byte, pw string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}
