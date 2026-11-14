package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesConsole(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "locklyctl-mqtt") {
		t.Fatal("console did not render")
	}
}
