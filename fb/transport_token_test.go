package fb

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
)

type stubRoundTripper struct {
	req  *http.Request
	resp *http.Response
	err  error
}

func (s *stubRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	s.req = r
	if s.resp != nil {
		return s.resp, s.err
	}

	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, s.err
}

func appSecretProof(clientKey, token string) string {
	h := hmac.New(sha256.New, []byte(clientKey))
	h.Write([]byte(token))

	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestTokenTransportRoundTrip(t *testing.T) {
	const (
		token     = "the-access-token"
		pageToken = "the-page-token"
		clientKey = "the-app-secret"
	)

	tests := []struct {
		name          string
		clientKey     string
		ctx           context.Context
		expectedToken string
		wantProof     bool
	}{
		{
			name:          "non-empty clientKey sends appsecret_proof for the access token",
			clientKey:     clientKey,
			ctx:           context.Background(),
			expectedToken: token,
			wantProof:     true,
		},
		{
			name:          "empty clientKey omits appsecret_proof entirely",
			clientKey:     "",
			ctx:           context.Background(),
			expectedToken: token,
			wantProof:     false,
		},
		{
			name:          "context page token with non-empty clientKey computes proof over the page token",
			clientKey:     clientKey,
			ctx:           SetPageAccessToken(context.Background(), pageToken),
			expectedToken: pageToken,
			wantProof:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := &stubRoundTripper{}
			transport := newTokenTransport(token, tt.clientKey, next)

			req, err := http.NewRequestWithContext(tt.ctx, http.MethodGet, "https://graph.facebook.com/v25.0/me", nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}

			if _, err := transport.RoundTrip(req); err != nil {
				t.Fatalf("RoundTrip returned error: %v", err)
			}

			q := next.req.URL.Query()

			if got := q.Get("access_token"); got != tt.expectedToken {
				t.Errorf("access_token = %q, want %q", got, tt.expectedToken)
			}

			if !tt.wantProof {
				if q.Has("appsecret_proof") {
					t.Errorf("appsecret_proof present with empty clientKey: %q", q.Get("appsecret_proof"))
				}

				return
			}

			if !q.Has("appsecret_proof") {
				t.Fatal("appsecret_proof missing with non-empty clientKey")
			}

			want := appSecretProof(tt.clientKey, tt.expectedToken)
			if got := q.Get("appsecret_proof"); got != want {
				t.Errorf("appsecret_proof = %q, want %q", got, want)
			}
		})
	}
}
