package auth

import (
	"testing"
	"net/http"
	"errors"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectErr   error
	}{
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			expectedKey: "",
			expectErr:   errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - too short",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectErr:   errors.New("malformed authorization header"),
		},
		{
			name: "Valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			expectedKey: "abc123",
			expectErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if (err != nil && tt.expectErr == nil) || (err == nil && tt.expectErr != nil) {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}

			if err != nil && tt.expectErr != nil && err.Error() != tt.expectErr.Error() {
				t.Errorf("expected error message %q, got %q", tt.expectErr.Error(), err.Error())
			}
		})
	}
}
