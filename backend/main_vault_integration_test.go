package main

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

func setupTestDB(t *testing.T) {
    t.Helper()

    db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
    if err != nil {
        t.Fatalf("open sqlite: %v", err)
    }
    if err := db.AutoMigrate(&User{}, &Secret{}); err != nil {
        t.Fatalf("automigrate: %v", err)
    }

    oldDB := DB
    DB = db
    t.Cleanup(func() { DB = oldDB })
}

func authedJSONRequest(method, path string, body any, username string) *http.Request {
    var raw []byte
    if body != nil {
        raw, _ = json.Marshal(body)
    }
    req := httptest.NewRequest(method, path, bytes.NewReader(raw))
    req.Header.Set("Content-Type", "application/json")
    req = req.WithContext(context.WithValue(req.Context(), usernameContextKey, username))
    return req
}

func TestPostVault_RejectsPlaintextFields(t *testing.T) {
    setupTestDB(t)

    if err := DB.Create(&User{Username: "alice", PasswordHash: "zkv1$test$test"}).Error; err != nil {
        t.Fatalf("seed user: %v", err)
    }

    req := authedJSONRequest(http.MethodPost, "/api/v1/vault", map[string]string{
        "site_name":               "github", // unknown field -> reject
        "encrypted_site_name":     b64Bytes(16, 0x11),
        "site_name_iv":            b64Bytes(12, 0x12),
        "encrypted_site_username": b64Bytes(16, 0x13),
        "site_username_iv":        b64Bytes(12, 0x14),
        "encrypted_password":      b64Bytes(16, 0x15),
        "iv":                      b64Bytes(12, 0x16),
        "enc_version":             "v1",
    }, "alice")

    rr := httptest.NewRecorder()
    (&VaultServer{}).PostApiV1Vault(rr, req)

    if rr.Code != http.StatusBadRequest {
        t.Fatalf("expected 400, got %d (%s)", rr.Code, rr.Body.String())
    }
}

func TestVault_EncryptedRoundTrip_NoPlaintextLeak(t *testing.T) {
    setupTestDB(t)

    if err := DB.Create(&User{Username: "alice", PasswordHash: "zkv1$test$test"}).Error; err != nil {
        t.Fatalf("seed user: %v", err)
    }

    postReq := authedJSONRequest(http.MethodPost, "/api/v1/vault", map[string]string{
        "encrypted_site_name":     b64Bytes(16, 0x21),
        "site_name_iv":            b64Bytes(12, 0x22),
        "encrypted_site_username": b64Bytes(16, 0x23),
        "site_username_iv":        b64Bytes(12, 0x24),
        "encrypted_password":      b64Bytes(16, 0x25),
        "iv":                      b64Bytes(12, 0x26),
        "enc_version":             "v1",
    }, "alice")

    postRR := httptest.NewRecorder()
    (&VaultServer{}).PostApiV1Vault(postRR, postReq)
    if postRR.Code != http.StatusCreated {
        t.Fatalf("expected 201, got %d (%s)", postRR.Code, postRR.Body.String())
    }

    getReq := authedJSONRequest(http.MethodGet, "/api/v1/vault", nil, "alice")
    getRR := httptest.NewRecorder()
    (&VaultServer{}).GetApiV1Vault(getRR, getReq)
    if getRR.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d (%s)", getRR.Code, getRR.Body.String())
    }

    var out []map[string]any
    if err := json.Unmarshal(getRR.Body.Bytes(), &out); err != nil {
        t.Fatalf("decode response: %v", err)
    }
    if len(out) != 1 {
        t.Fatalf("expected 1 row, got %d", len(out))
    }

    if _, ok := out[0]["site_name"]; ok {
        t.Fatal("plaintext site_name leaked")
    }
    if _, ok := out[0]["site_username"]; ok {
        t.Fatal("plaintext site_username leaked")
    }
}

func TestEnforceNoLegacyPasswordHashes(t *testing.T) {
    setupTestDB(t)

    if err := DB.Create(&User{Username: "legacy", PasswordHash: b64Bytes(32, 0x31)}).Error; err != nil {
        t.Fatalf("seed legacy user: %v", err)
    }
    if err := enforceNoLegacyPasswordHashes(); err == nil {
        t.Fatal("expected failure for legacy password hash rows")
    }

    if err := DB.Exec("DELETE FROM users").Error; err != nil {
        t.Fatalf("clear users: %v", err)
    }

    verifier, err := createPasswordVerifier(b64Bytes(32, 0x32))
    if err != nil {
        t.Fatalf("create verifier: %v", err)
    }
    if err := DB.Create(&User{Username: "modern", PasswordHash: verifier}).Error; err != nil {
        t.Fatalf("seed modern user: %v", err)
    }
    if err := enforceNoLegacyPasswordHashes(); err != nil {
        t.Fatalf("expected pass for strict verifier rows, got %v", err)
    }
}