package auth

import (
	"net/http"
	"regexp"
	"testing"
)

func TestApiKeyEmptyHeader(t *testing.T) {
	header := make(http.Header, 1)
	want := regexp.MustCompile(`^$`)
	key, err := GetAPIKey(header)
	if !want.MatchString(key) || err == nil {
		t.Fatalf(`GetAPIKey([empty header]) = %q, %v, want match for %#q, ErrNoAuthIncluded`, key, err, want)
	}
}

func TestMalformedApiKey(t *testing.T) {
	header := make(http.Header, 1)
	header.Set("Authorization", "ThisIsATestKey")
	want := regexp.MustCompile(`^$`)
	key, err := GetAPIKey(header)
	if !want.MatchString(key) || err == nil {
		t.Fatalf(`GetAPIKey([Malformed Header]) = %q, %v, want match for %#q, malformed authorization header`, key, err, want)
	}
}

func TestApiKey(t *testing.T) {
	header := make(http.Header, 1)
	header.Set("Authorization", "ApiKey ThisIsATestKey")
	want := regexp.MustCompile(`.*`)
	key, err := GetAPIKey(header)
	if !want.MatchString(key) || err != nil {
		t.Fatalf(`GetAPIKey([Correct Header]) = %q, %v, want match for %#q, nil`, key, err, want)
	}
}
