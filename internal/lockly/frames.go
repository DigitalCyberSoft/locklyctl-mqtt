package lockly

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// DatePermanent is the validity window meaning "never expires" (FF x10).
const DatePermanent = "FFFFFFFFFFFFFFFFFFFF"

// Access-user type bytes (features.py UT_*).
const (
	UserOwner       = 0x21
	UserFamily      = 0x22
	UserGuestPeriod = 0x12
	UserGuestWeekly = 0x42
	UserGuestOnce   = 0x32
	PwdIDAny        = 0xFF // let the lock choose the slot
)

// encParts returns the <enc_mc> field, its length byte, and the AES key.
func encParts(mc, uuid string) (encMc, mcLen string, key []byte, err error) {
	encMc, err = EncryptMasterCode(mc, uuid)
	if err != nil {
		return "", "", nil, err
	}
	key, err = DeriveAESKey(mc, uuid)
	if err != nil {
		return "", "", nil, err
	}
	return encMc, fmt.Sprintf("%d", len(encMc)/2), key, nil
}

// le2 is two bytes little-endian, uppercase hex (getCmdLenString; _le2).
func le2(n int) string {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(n))
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// userID is intToLittleHex(userID) + intToLittleHex(adminID), 2 bytes each
// (Cmd.getUserId; _user_id).
func userID(user, admin int) string { return le2(user) + le2(admin) }

func digitBytes(digits string) ([]byte, error) {
	out := make([]byte, len(digits))
	for i, c := range []byte(digits) {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("not all digits")
		}
		out[i] = c - '0'
	}
	return out, nil
}

func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// TimeZoneByte encodes a whole-hour UTC offset (SetTimeZoneCmd.getZone;
// features.time_zone_byte): bit 7 set, bit 4 the half-hour flag (never set
// here), bit 3 the sign (1 at or east of UTC), bits 0-3 the hours.
// +8 -> 0x98, UTC -> 0x90, -5 -> 0x85.
func TimeZoneByte(hours int) byte {
	b := byte(0x80)
	if hours >= 0 {
		b |= 0x10
	}
	h := hours
	if h < 0 {
		h = -h
	}
	return b | byte(h&0x0F)
}

// BuildTimeZoneSet is 0x33 SetTimeZoneCmd, mode 1 (set), after a status query
// whose nonce is passed here (features.build_time_zone_set).
func BuildTimeZoneSet(mc, uuid, nonce string, hours int) (string, error) {
	encMc, mcLen, key, err := encParts(mc, uuid)
	if err != nil {
		return "", err
	}
	raw := AssembleFields("33", mcLen, encMc, "1", fmt.Sprintf("%02X", TimeZoneByte(hours)), strings.ToUpper(nonce))
	return AESWrap(raw, key, EncryptTypeAES)
}

// AccessUser is one person's record to push to an access-user lock (Visage).
type AccessUser struct {
	UserType    int    // UserOwner / UserFamily / UserGuest*
	PwdID       int    // credential slot, or PwdIDAny to let the lock choose
	UserID      int    // the account's user id for this person
	AdminID     int    // the owner/admin id (0 for owner-created)
	PIN         string // decimal PIN, "" removes the PIN but keeps the user
	Date        string // DatePermanent or a period window; see DatePeriod
	MultiVerify int    // 1 = single credential unlocks
}

// BuildAccessUserSet is 0x73 AccessUser115Cmd mode 1: write or refresh a
// person on the lock (features.build_access_user_set).
func (u AccessUser) BuildAccessUserSet(mc, uuid, nonce string) (string, error) {
	encMc, mcLen, key, err := encParts(mc, uuid)
	if err != nil {
		return "", err
	}
	date := u.Date
	if date == "" {
		date = DatePermanent
	}
	mv := u.MultiVerify
	if mv == 0 {
		mv = 1
	}
	raw := AssembleFields("73", mcLen, encMc, "1",
		fmt.Sprintf("%X", u.UserType), le2(u.PwdID), userID(u.UserID, u.AdminID),
		date, fmt.Sprintf("%X", len(u.PIN)), ExpandDigits(u.PIN),
		fmt.Sprintf("%d", mv), strings.ToUpper(nonce))
	return AESWrap(raw, key, EncryptTypeAES)
}

// BuildAccessUserDelete is 0x73 mode 2: remove a person and everything on them
// (features.build_access_user_delete).
func (u AccessUser) BuildAccessUserDelete(mc, uuid, nonce string) (string, error) {
	encMc, mcLen, key, err := encParts(mc, uuid)
	if err != nil {
		return "", err
	}
	raw := AssembleFields("73", mcLen, encMc, "2",
		fmt.Sprintf("%X", u.UserType), le2(u.PwdID), userID(u.UserID, u.AdminID),
		strings.ToUpper(nonce))
	return AESWrap(raw, key, EncryptTypeAES)
}

// BuildSetMasterCode is the 01 01 setup frame (XOR-masked, not AES): the
// Activation Card code and 8 random digits (bind.build_set_master_code).
func BuildSetMasterCode(code, rnd string) (string, error) {
	codeB, err := digitBytes(code)
	if err != nil {
		return "", fmt.Errorf("activation code: %w", err)
	}
	rndB, err := digitBytes(rnd)
	if err != nil {
		return "", fmt.Errorf("random digits: %w", err)
	}
	raw := append([]byte{0x01, 0x01, 0x08}, codeB...)
	raw = append(raw, rndB...)
	return strings.ToUpper(hex.EncodeToString(BuildBLEFrame(xorBytes(raw, codeB), 3))), nil
}

// BuildStartMasterCode is the 01 04 setup frame: put the new master code in
// force (bind.build_start_master_code).
func BuildStartMasterCode(code, mc, deviceID string) (string, error) {
	codeB, err := digitBytes(code)
	if err != nil {
		return "", fmt.Errorf("activation code: %w", err)
	}
	mcB, err := digitBytes(mc)
	if err != nil {
		return "", fmt.Errorf("master code: %w", err)
	}
	devB, err := hex.DecodeString(deviceID)
	if err != nil {
		return "", fmt.Errorf("device id not hex: %w", err)
	}
	raw := append([]byte{0x01, 0x04, 0x08}, mcB...)
	raw = append(raw, devB...)
	return strings.ToUpper(hex.EncodeToString(BuildBLEFrame(xorBytes(raw, codeB), 3))), nil
}
