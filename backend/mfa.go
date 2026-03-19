package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "net/http"
    "os"
    "regexp"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
    "gorm.io/gorm"
)

var (
    mfaEncKey []byte
    otpCodeRe = regexp.MustCompile(`^\d{6}$`)
)

const (
    mfaIssuer       = "SecureVault"
    mfaPurposeLogin = "mfa_login"
    mfaPurposeSetup = "mfa_setup"
    mfaLoginTTL     = 5 * time.Minute
    mfaSetupTTL     = 10 * time.Minute
)

type MFAClaims struct {
    Username string `json:"username"`
    Purpose  string `json:"purpose"`
    Secret   string `json:"secret,omitempty"`
    jwt.RegisteredClaims
}

func initMFAFromEnv() error {
    raw := strings.TrimSpace(os.Getenv("MFA_ENC_KEY"))
    if len(raw) != 32 {
        return fmt.Errorf("MFA_ENC_KEY must be exactly 32 characters")
    }
    mfaEncKey = []byte(raw)
    return nil
}

func newMFAToken(username, purpose, secret string, ttl time.Duration) (string, error) {
    claims := &MFAClaims{
        Username: username,
        Purpose:  purpose,
        Secret:   secret,
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   username,
            Issuer:    jwtIssuer,
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtKey)
}

func parseMFAToken(tokenString, expectedPurpose string) (*MFAClaims, error) {
    claims := &MFAClaims{}
    token, err := jwt.ParseWithClaims(
        tokenString,
        claims,
        func(token *jwt.Token) (any, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, errors.New("unexpected signing method")
            }
            return jwtKey, nil
        },
        jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
        jwt.WithIssuer(jwtIssuer),
        jwt.WithLeeway(30*time.Second),
    )
    if err != nil || !token.Valid {
        return nil, errors.New("invalid mfa token")
    }
    if claims.Username == "" || claims.Subject != claims.Username || claims.Purpose != expectedPurpose {
        return nil, errors.New("invalid mfa token claims")
    }
    return claims, nil
}

func encryptMFASecret(secret string) (string, error) {
    block, err := aes.NewCipher(mfaEncKey)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
    out := append(nonce, ciphertext...)
    return base64.RawStdEncoding.EncodeToString(out), nil
}

func decryptMFASecret(secretEnc string) (string, error) {
    raw, err := decodeBase64(secretEnc)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(mfaEncKey)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    if len(raw) <= gcm.NonceSize() {
        return "", errors.New("invalid encrypted secret")
    }

    nonce := raw[:gcm.NonceSize()]
    ciphertext := raw[gcm.NonceSize():]
    plain, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plain), nil
}

func isValidOTPCode(code string) bool {
    return otpCodeRe.MatchString(strings.TrimSpace(code))
}

func verifyTOTP(secret, code string) bool {
    ok, err := totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now().UTC(), totp.ValidateOpts{
        Period:    30,
        Skew:      1,
        Digits:    otp.DigitsSix,
        Algorithm: otp.AlgorithmSHA1,
    })
    return err == nil && ok
}

// (GET /api/v1/auth/mfa/status)
func (v *VaultServer) GetApiV1AuthMfaStatus(w http.ResponseWriter, r *http.Request) {
    username, ok := usernameFromRequest(r)
    if !ok {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    var user User
    if err := DB.Where("username = ?", username).First(&user).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            writeError(w, http.StatusUnauthorized, "unauthorized")
            return
        }
        writeError(w, http.StatusInternalServerError, "database error")
        return
    }

    writeJSON(w, http.StatusOK, map[string]any{
        "enabled": user.MFAEnabled,
    })
}

// (POST /api/v1/auth/mfa/setup/start)
func (v *VaultServer) PostApiV1AuthMfaSetupStart(w http.ResponseWriter, r *http.Request) {
    username, ok := usernameFromRequest(r)
    if !ok {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    var user User
    if err := DB.Where("username = ?", username).First(&user).Error; err != nil {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    if user.MFAEnabled {
        writeError(w, http.StatusConflict, "mfa already enabled")
        return
    }

    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      mfaIssuer,
        AccountName: username,
        SecretSize:  20,
        Digits:      otp.DigitsSix,
        Algorithm:   otp.AlgorithmSHA1,
        Period:      30,
    })
    if err != nil {
        writeError(w, http.StatusInternalServerError, "failed to start mfa setup")
        return
    }

    setupToken, err := newMFAToken(username, mfaPurposeSetup, key.Secret(), mfaSetupTTL)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "failed to create mfa setup token")
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{
        "setup_token": setupToken,
        "otpauth_url": key.URL(),
        "manual_key":  key.Secret(),
    })
}

// (POST /api/v1/auth/mfa/setup/confirm)
func (v *VaultServer) PostApiV1AuthMfaSetupConfirm(w http.ResponseWriter, r *http.Request) {
    username, ok := usernameFromRequest(r)
    if !ok {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    var input struct {
        SetupToken string `json:"setup_token"`
        Code       string `json:"code"`
    }
    if err := decodeJSON(w, r, &input, maxAuthBodyBytes); err != nil {
        writeDecodeError(w, err)
        return
    }

    input.SetupToken = strings.TrimSpace(input.SetupToken)
    input.Code = strings.TrimSpace(input.Code)

    if input.SetupToken == "" || !isValidOTPCode(input.Code) {
        writeError(w, http.StatusBadRequest, "setup_token and valid 6-digit code are required")
        return
    }

    claims, err := parseMFAToken(input.SetupToken, mfaPurposeSetup)
    if err != nil || claims.Username != username || claims.Secret == "" {
        writeError(w, http.StatusUnauthorized, "invalid mfa setup token")
        return
    }

    if !verifyTOTP(claims.Secret, input.Code) {
        writeError(w, http.StatusUnauthorized, "invalid mfa code")
        return
    }

    enc, err := encryptMFASecret(claims.Secret)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "failed to store mfa secret")
        return
    }

    if err := DB.Model(&User{}).
        Where("username = ?", username).
        Updates(map[string]any{
            "mfa_enabled":    true,
            "mfa_secret_enc": enc,
        }).Error; err != nil {
        writeError(w, http.StatusInternalServerError, "database error")
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"message": "mfa enabled"})
}

// (POST /api/v1/auth/mfa/disable)
func (v *VaultServer) PostApiV1AuthMfaDisable(w http.ResponseWriter, r *http.Request) {
    username, ok := usernameFromRequest(r)
    if !ok {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    var input struct {
        Code string `json:"code"`
    }
    if err := decodeJSON(w, r, &input, maxAuthBodyBytes); err != nil {
        writeDecodeError(w, err)
        return
    }
    input.Code = strings.TrimSpace(input.Code)

    if !isValidOTPCode(input.Code) {
        writeError(w, http.StatusBadRequest, "valid 6-digit code is required")
        return
    }

    var user User
    if err := DB.Where("username = ?", username).First(&user).Error; err != nil {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    if !user.MFAEnabled || user.MFASecretEnc == "" {
        writeError(w, http.StatusBadRequest, "mfa is not enabled")
        return
    }

    secret, err := decryptMFASecret(user.MFASecretEnc)
    if err != nil || !verifyTOTP(secret, input.Code) {
        writeError(w, http.StatusUnauthorized, "invalid mfa code")
        return
    }

    if err := DB.Model(&User{}).
        Where("id = ?", user.ID).
        Updates(map[string]any{
            "mfa_enabled":    false,
            "mfa_secret_enc": "",
        }).Error; err != nil {
        writeError(w, http.StatusInternalServerError, "database error")
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"message": "mfa disabled"})
}

// (POST /api/v1/auth/mfa/verify-login)
func (v *VaultServer) PostApiV1AuthMfaVerifyLogin(w http.ResponseWriter, r *http.Request) {
    var input struct {
        MFAToken string `json:"mfa_token"`
        Code     string `json:"code"`
    }
    if err := decodeJSON(w, r, &input, maxAuthBodyBytes); err != nil {
        writeDecodeError(w, err)
        return
    }

    input.MFAToken = strings.TrimSpace(input.MFAToken)
    input.Code = strings.TrimSpace(input.Code)

    if input.MFAToken == "" || !isValidOTPCode(input.Code) {
        writeError(w, http.StatusBadRequest, "mfa_token and valid 6-digit code are required")
        return
    }

    claims, err := parseMFAToken(input.MFAToken, mfaPurposeLogin)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "invalid mfa token")
        return
    }

    var user User
    if err := DB.Where("username = ?", claims.Username).First(&user).Error; err != nil {
        writeError(w, http.StatusUnauthorized, "invalid mfa token")
        return
    }
    if !user.MFAEnabled || user.MFASecretEnc == "" {
        writeError(w, http.StatusUnauthorized, "mfa is not enabled")
        return
    }

    secret, err := decryptMFASecret(user.MFASecretEnc)
    if err != nil || !verifyTOTP(secret, input.Code) {
        writeError(w, http.StatusUnauthorized, "invalid mfa code")
        return
    }

    token, err := GenerateJWT(user.Username)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "failed to generate token")
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{
        "message": "login successful",
        "token":   token,
    })
}