package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		header        http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "No Authorization Header",
			header:        http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization Header - Missing ApiKey prefix",
			header:        http.Header{"Authorization": []string{"Bearer somekey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Malformed Authorization Header - No space",
			header:        http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Valid Authorization Header",
			header:        http.Header{"Authorization": []string{"ApiKey mysecretkey"}},
			expectedKey:   "mysecretkey",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.header)
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}
			if err != nil && tt.expectedError != nil {
				if err.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
				}
			} else if err != tt.expectedError {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
			}
		})
	}
}
