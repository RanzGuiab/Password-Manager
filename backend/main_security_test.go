package main

import (
    "bytes"
    "encoding/base64"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func b64Bytes(n int, fill byte) string {
    return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n))
}

func TestPasswordVerifier_StrictOnly(t *testing.T) {
    clientHash := b64Bytes(32, 0x11)
    otherHash := b64Bytes(32, 0x22)

    verifier, err := createPasswordVerifier(clientHash)
    if err != nil {
        t.Fatalf("createPasswordVerifier() error = %v", err)
    }
    if !strings.HasPrefix(verifier, verifierPrefix+"$") {
        t.Fatalf("expected verifier prefix %q", verifierPrefix+"$")
    }

    if !verifyPasswordVerifier(clientHash, verifier) {
        t.Fatal("expected valid verifier check to pass")
    }
    if verifyPasswordVerifier(otherHash, verifier) {
        t.Fatal("expected wrong hash verification to fail")
    }
    if verifyPasswordVerifier(clientHash, clientHash) {
        t.Fatal("legacy raw password_hash fallback must be disabled")
    }
}

func TestValidationHelpers(t *testing.T) {
    if !isValidClientPasswordHash(b64Bytes(32, 0x01)) {
        t.Fatal("expected valid client password hash")
    }
    if isValidClientPasswordHash(b64Bytes(31, 0x01)) {
        t.Fatal("expected invalid short hash")
    }
    if !isValidIV(b64Bytes(12, 0x02)) {
        t.Fatal("expected valid IV")
    }
    if isValidIV(b64Bytes(11, 0x02)) {
        t.Fatal("expected invalid IV length")
    }
    if !isValidCiphertext(b64Bytes(16, 0x03)) {
        t.Fatal("expected valid ciphertext")
    }
    if isValidCiphertext(b64Bytes(15, 0x03)) {
        t.Fatal("expected invalid short ciphertext")
    }
}

func TestDecodeJSONStrict(t *testing.T) {
    rr := httptest.NewRecorder()

    var dst struct {
        Username string `json:"username"`
    }

    reqUnknown := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"alice","extra":1}`))
    reqUnknown.Header.Set("Content-Type", "application/json")
    if err := decodeJSON(rr, reqUnknown, &dst, 1024); err == nil {
        t.Fatal("expected unknown field decode failure")
    }

    reqMulti := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"alice"}{"x":1}`))
    reqMulti.Header.Set("Content-Type", "application/json")
    if err := decodeJSON(rr, reqMulti, &dst, 1024); err == nil {
        t.Fatal("expected multi-object decode failure")
    }

    reqWrongCT := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"alice"}`))
    reqWrongCT.Header.Set("Content-Type", "text/plain")
    if err := decodeJSON(rr, reqWrongCT, &dst, 1024); err == nil {
        t.Fatal("expected content-type decode failure")
    }
}

func TestJWTMiddleware_ValidAndTamperedToken(t *testing.T) {
    oldJWTKey := jwtKey
    jwtKey = []byte(strings.Repeat("k", 32))
    defer func() { jwtKey = oldJWTKey }()

    token, err := GenerateJWT("alice")
    if err != nil {
        t.Fatalf("GenerateJWT() error = %v", err)
    }

    h := JWTMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        u, ok := usernameFromRequest(r)
        if !ok || u != "alice" {
            t.Fatalf("expected username alice in context, got %q", u)
        }
        w.WriteHeader(http.StatusNoContent)
    }))

    okReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
    okReq.Header.Set("Authorization", "Bearer "+token)
    okRR := httptest.NewRecorder()
    h.ServeHTTP(okRR, okReq)
    if okRR.Code != http.StatusNoContent {
        t.Fatalf("expected 204, got %d", okRR.Code)
    }

    badReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
    badReq.Header.Set("Authorization", "Bearer "+token+"tampered")
    badRR := httptest.NewRecorder()
    h.ServeHTTP(badRR, badReq)
    if badRR.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d", badRR.Code)
    }
}

func TestLoginRateLimiter(t *testing.T) {
    key := "alice|127.0.0.1"

    loginAttemptsMu.Lock()
    old := loginAttempts
    loginAttempts = make(map[string]loginAttemptState)
    loginAttemptsMu.Unlock()

    defer func() {
        loginAttemptsMu.Lock()
        loginAttempts = old
        loginAttemptsMu.Unlock()
    }()

    for i := 0; i < loginMaxFailures; i++ {
        recordLoginFailure(key)
    }

    locked, _ := isLoginLocked(key)
    if !locked {
        t.Fatal("expected lock after max failures")
    }

    clearLoginFailures(key)
    locked, _ = isLoginLocked(key)
    if locked {
        t.Fatal("expected key to be cleared")
    }
}