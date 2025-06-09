package main

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
		shouldError   bool
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123def456"},
			},
			expectedKey: "abc123def456",
			shouldError: false,
		},
		{
			name: "valid API key with complex key",
			headers: http.Header{
				"Authorization": []string{"ApiKey sk-1234567890abcdef"},
			},
			expectedKey: "sk-1234567890abcdef",
			shouldError: false,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedError: "no authorization header included",
			shouldError:   true,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedError: "no authorization header included",
			shouldError:   true,
		},
		{
			name: "malformed header - missing API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name: "malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123def456"},
			},
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name: "malformed header - no prefix",
			headers: http.Header{
				"Authorization": []string{"abc123def456"},
			},
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name: "case sensitive prefix",
			headers: http.Header{
				"Authorization": []string{"apikey abc123def456"},
			},
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name: "extra spaces in header",
			headers: http.Header{
				"Authorization": []string{"ApiKey  abc123def456"},
			},
			expectedKey: "", // second element will be empty
			shouldError: false,
		},
		{
			name: "multiple spaces between prefix and key",
			headers: http.Header{
				"Authorization": []string{"ApiKey   abc123def456"},
			},
			expectedKey: "", // splits on first space, so we get empty string
			shouldError: false,
		},
		{
			name: "API key with spaces (multiple parts)",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123 def456"},
			},
			expectedKey: "abc123", // only returns first part after split
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := auth.GetAPIKey(tt.headers)

			if tt.shouldError {
				if err == nil {
					t.Errorf("GetAPIKey() expected error but got none")
					return
				}
				if err.Error() != tt.expectedError {
					t.Errorf("GetAPIKey() error = %q; want %q", err.Error(), tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("GetAPIKey() unexpected error: %v", err)
				return
			}

			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %q; want %q", key, tt.expectedKey)
			}
		})
	}
}
