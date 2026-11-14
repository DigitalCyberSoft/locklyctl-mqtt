package lockly

import "testing"

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
