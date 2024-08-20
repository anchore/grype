package commands

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anchore/clio"
)

func Test_ListingUserAgent(t *testing.T) {
	listingFile := "/listing.json"

	got := ""

	// setup mock
	handler := http.NewServeMux()
	handler.HandleFunc(listingFile, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.0.0"))
	})
	mockSrv := httptest.NewServer(handler)
	defer mockSrv.Close()

	dbOptions := *dbOptionsDefault(clio.Identification{
		Name:    "the-app",
		Version: "v3.2.1",
	})
	dbOptions.DB.RequireUpdateCheck = true
	dbOptions.DB.UpdateURL = mockSrv.URL + listingFile

	_ = runDBList(&dbListOptions{
		Output:    "",
		DBOptions: dbOptions,
	})

	if got != "the-app v3.2.1" {
		t.Errorf("expected User-Agent header to match, got: %v", got)
	}
}
