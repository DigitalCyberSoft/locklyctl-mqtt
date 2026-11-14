package lockly

import (
	"testing"
	"time"
)

func TestBuildStatusQuery(t *testing.T) {
	now := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	if got := TimestampHex(now); got != "1a0b0e091e00" {
		t.Fatalf("TimestampHex = %s", got)
	}
	got, err := BuildStatusQuery(vecMC, vecUUID, now)
	if err != nil {
		t.Fatal(err)
	}
	want := "A1B2C3D42800EE76A0AC7C82DB63D4825EB9E43A33EFEBF4733C04F38836FD6B452E9CEB6AABF50D"
	if got != want {
		t.Fatalf("status query mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestParseStatusReply(t *testing.T) {
	// 27 bytes: fw(4) status(1) v(4) time(6) prog(1) autolock(2) locktype(1) nonce(8)
	d := "1A0B0E22" + "02" + "C803C803" + "1A0B0E091E00" + "00" + "0500" + "69" +
		"1122334455667788" + "0000"
	r, err := ParseStatusReply(d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Nonce != "1122334455667788" {
		t.Fatalf("nonce = %s", r.Nonce)
	}
	if r.FirmwareVersion != "1A0B0E22" {
		t.Fatalf("fw = %s", r.FirmwareVersion)
	}
	if _, err := ParseStatusReply("00"); err == nil {
		t.Fatal("expected error for short payload")
	}
}

func TestTimeZoneByte(t *testing.T) {
	cases := []struct {
		hours int
		want  byte
	}{{8, 0x98}, {0, 0x90}, {-5, 0x85}}
	for _, c := range cases {
		if got := TimeZoneByte(c.hours); got != c.want {
			t.Fatalf("TimeZoneByte(%d) = %02X, want %02X", c.hours, got, c.want)
		}
	}
}

func TestBuildTimeZoneSet(t *testing.T) {
	got, err := BuildTimeZoneSet(vecMC, vecUUID, vecNonce, 8)
	if err != nil {
		t.Fatal(err)
	}
	want := "A1B2C3D428009DDB3FA83A64F9FB80A7488AE3538C32EFAEEABEA41CF239C57E85D435B6F356C579"
	if got != want {
		t.Fatalf("time zone frame mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestBuildAccessUserSet(t *testing.T) {
	u := AccessUser{UserType: 0x24, PwdID: 5, UserID: 7, PIN: "135790", Date: DatePermanent}
	got, err := u.BuildAccessUserSet(vecMC, vecUUID, vecNonce)
	if err != nil {
		t.Fatal(err)
	}
	want := "A1B2C3D43800CEC828BC579673B3989371F79E131271BC9E81405E28B84BB52D52759B7F4451084DD7544DCD98CB05D0F94A52AD6CBD45C3"
	if got != want {
		t.Fatalf("access-user frame mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestDateHelpers(t *testing.T) {
	s := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	e := time.Date(2027, 1, 2, 18, 5, 0, 0, time.UTC)
	if got := DatePeriodHex(s, e); got != "1A0B0E091E1B01021205" {
		t.Fatalf("DatePeriodHex = %s", got)
	}
	if got := DateWeeklyHex(0x7F); got != "7F000018000000000000" {
		t.Fatalf("DateWeeklyHex = %s", got)
	}
	if got := DateExpiredHex(); len(got) != 20 {
		t.Fatalf("DateExpiredHex wrong length: %s", got)
	}
}

func TestBuildSetMasterCode(t *testing.T) {
	got, err := BuildSetMasterCode("24681357", "90817263")
	if err != nil {
		t.Fatal(err)
	}
	want := "A1B2C3D41B0003050E0A05050D0601010101010B040000020503D5"
	if got != want {
		t.Fatalf("01 01 frame mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestBuildStartMasterCode(t *testing.T) {
	got, err := BuildStartMasterCode("24681357", "13572468", "cc00112233445566778899aa")
	if err != nil {
		t.Fatal(err)
	}
	want := "A1B2C3D41F0003000E090206020506020EC4011227344651607F899AAF0365"
	if got != want {
		t.Fatalf("01 04 frame mismatch:\n got %s\nwant %s", got, want)
	}
}
