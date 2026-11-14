package lockly

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Vectors generated from locklyctl (Python) so this port stays byte-identical:
//
//	mc="24860092" uuid="2d0023003030471333363838" nonce="1122334455667788"
const (
	vecMC    = "24860092"
	vecUUID  = "2d0023003030471333363838"
	vecNonce = "1122334455667788"
)

func TestDeriveAESKey(t *testing.T) {
	key, err := DeriveAESKey(vecMC, vecUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != "2f042b0630304e113132303e2d002300" {
		t.Fatalf("key = %s", got)
	}
}

func TestDeriveAESKeyRejectsBadInput(t *testing.T) {
	if _, err := DeriveAESKey("12x45678", vecUUID); err == nil {
		t.Fatal("expected error for non-digit master code")
	}
	if _, err := DeriveAESKey(vecMC, "zz"); err == nil {
		t.Fatal("expected error for non-hex uuid")
	}
	if _, err := DeriveAESKey(vecMC, "2d00230030"); err == nil {
		t.Fatal("expected error for short uuid")
	}
}

func TestEncryptMasterCode(t *testing.T) {
	got, err := EncryptMasterCode(vecMC, vecUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2F042B0630304E11" {
		t.Fatalf("enc_mc = %s", got)
	}
}

func TestCRC8(t *testing.T) {
	cases := []struct {
		in   string
		want byte
	}{
		{"A1B2C3D4", 217},
		{"0001020304", 254},
	}
	for _, c := range cases {
		b, _ := hex.DecodeString(c.in)
		if got := CRC8(b); got != c.want {
			t.Fatalf("CRC8(%s) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestBuildBLEFrame(t *testing.T) {
	payload, _ := hex.DecodeString("0011")
	got := strings.ToUpper(hex.EncodeToString(BuildBLEFrame(payload, 5)))
	if got != "A1B2C3D40A0000110525" {
		t.Fatalf("frame = %s", got)
	}
}

func TestAssembleFields(t *testing.T) {
	got := AssembleFields("33", "8", "A1B2", "1", "98", strings.ToUpper(vecNonce))
	if got != "3308A1B201981122334455667788" {
		t.Fatalf("assemble = %s", got)
	}
	// an empty field drops out entirely
	if got := AssembleFields("AB", "", "CD"); got != "ABCD" {
		t.Fatalf("empty field not dropped: %s", got)
	}
}

func TestExpandDigits(t *testing.T) {
	if got := ExpandDigits("135790"); got != "010305070900" {
		t.Fatalf("expand = %s", got)
	}
	if got := ExpandDigits(""); got != "" {
		t.Fatalf("expand empty = %q", got)
	}
}

// DecryptAck recovers the plaintext of a real response frame (magic + length +
// 0A33 CmdType + ciphertext + CRC). Vector from locklyctl's AES + crc8.
func TestDecryptAck(t *testing.T) {
	resp := "A1B2C3D41A000A336449583D44DDC77584C106D28074326385"
	want := "0033AABBCCDD00000000000000000000"
	got, ok := DecryptAck(resp, vecMC, vecUUID)
	if !ok {
		t.Fatal("DecryptAck returned ok=false for a valid response frame")
	}
	if got != want {
		t.Fatalf("DecryptAck = %s, want %s", got, want)
	}
}

func TestDecryptAckRejectsShortFrame(t *testing.T) {
	// A lock rejection is a short unencrypted 0C frame; DecryptAck must decline.
	if _, ok := DecryptAck("A1B2C3D40C000CFF", vecMC, vecUUID); ok {
		t.Fatal("DecryptAck accepted a short rejection frame")
	}
	if _, ok := DecryptAck("", vecMC, vecUUID); ok {
		t.Fatal("DecryptAck accepted an empty frame")
	}
}
