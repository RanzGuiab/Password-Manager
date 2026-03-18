package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

type contextKey string

const (
	usernameContextKey contextKey = "username"
	jwtIssuer                     = "securevault-api"

	maxAuthBodyBytes  int64 = 8 * 1024
	maxVaultBodyBytes int64 = 64 * 1024

	maxCiphertextBytes = 16 * 1024

	verifierPrefix         = "zkv1"
	verifierSaltLen        = 16
	verifierTime    uint32 = 3
	verifierMemory  uint32 = 64 * 1024
	verifierThreads uint8  = 2
	verifierKeyLen  uint32 = 32

	loginMaxFailures  = 5
	loginWindow       = 10 * time.Minute
	loginLockDuration = 15 * time.Minute
)

var (
	jwtKey []byte

	allowLegacyPasswordFallback bool
	enforceEncryptedMetadata    bool
	enableHSTS                  bool

	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,64}$`)

	loginAttemptsMu sync.Mutex
	loginAttempts   = make(map[string]loginAttemptState)
)

type loginAttemptState struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type VaultServer struct{}

type errorResponse struct {
	Error string `json:"error"`
}

func readBoolEnv(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("invalid %s=%q, using default=%v", key, raw, def)
		return def
	}
	return v
}

func initSecrets() error {
	jwtSecret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}
	jwtKey = []byte(jwtSecret)

	allowLegacyPasswordFallback = readBoolEnv("ALLOW_LEGACY_PASSWORD_HASH", false)
	enforceEncryptedMetadata = readBoolEnv("ENFORCE_ENCRYPTED_METADATA", true)
	enableHSTS = readBoolEnv("ENABLE_HSTS", false)

	if allowLegacyPasswordFallback {
		log.Printf("WARNING: ALLOW_LEGACY_PASSWORD_HASH=true")
	}
	if !enforceEncryptedMetadata {
		log.Printf("WARNING: ENFORCE_ENCRYPTED_METADATA=false")
	}
	return nil
}

func enforceNoLegacyPlaintextSecrets() error {
	if !enforceEncryptedMetadata {
		return nil
	}

	var count int64
	err := DB.Model(&Secret{}).
		Where("COALESCE(encrypted_site_name, '') = '' OR COALESCE(site_name_iv, '') = '' OR COALESCE(encrypted_site_username, '') = '' OR COALESCE(site_username_iv, '') = ''").
		Count(&count).Error
	if err != nil {
		return err
	}

	if count > 0 {
		return fmt.Errorf("found %d legacy/plaintext secret rows; migrate data or set ENFORCE_ENCRYPTED_METADATA=false temporarily", count)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if contentType := strings.TrimSpace(r.Header.Get("Content-Type")); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			return errors.New("content-type must be application/json")
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesErr):
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
	case strings.Contains(strings.ToLower(err.Error()), "content-type"):
		writeError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
	default:
		writeError(w, http.StatusBadRequest, "invalid JSON")
	}
}

func usernameFromRequest(r *http.Request) (string, bool) {
	username, ok := r.Context().Value(usernameContextKey).(string)
	return username, ok && username != ""
}

func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   username,
			Issuer:    jwtIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func decodeBase64(value string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func isValidUsername(username string) bool {
	return usernameRe.MatchString(username)
}

func isValidClientPasswordHash(passwordHash string) bool {
	decoded, err := decodeBase64(passwordHash)
	return err == nil && len(decoded) == 32
}

func isValidIV(iv string) bool {
	decoded, err := decodeBase64(iv)
	return err == nil && len(decoded) == 12
}

func isValidCiphertext(ciphertext string) bool {
	decoded, err := decodeBase64(ciphertext)
	return err == nil && len(decoded) >= 16 && len(decoded) <= maxCiphertextBytes
}

func createPasswordVerifier(clientHash string) (string, error) {
	salt := make([]byte, verifierSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	digest := argon2.IDKey(
		[]byte(clientHash),
		salt,
		verifierTime,
		verifierMemory,
		verifierThreads,
		verifierKeyLen,
	)

	return fmt.Sprintf(
		"%s$%s$%s",
		verifierPrefix,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

func secureStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func verifyPasswordVerifier(clientHash, stored string) bool {
	if strings.HasPrefix(stored, verifierPrefix+"$") {
		parts := strings.Split(stored, "$")
		if len(parts) != 3 || parts[0] != verifierPrefix {
			return false
		}

		salt, err := base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil || len(salt) != verifierSaltLen {
			return false
		}

		expected, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil || len(expected) == 0 {
			return false
		}

		actual := argon2.IDKey(
			[]byte(clientHash),
			salt,
			verifierTime,
			verifierMemory,
			verifierThreads,
			uint32(len(expected)),
		)

		return subtle.ConstantTimeCompare(expected, actual) == 1
	}

	if !allowLegacyPasswordFallback {
		return false
	}
	return secureStringEqual(stored, clientHash)
}

func needsVerifierUpgrade(stored string) bool {
	return !strings.HasPrefix(stored, verifierPrefix+"$")
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
}

func loginRateKey(r *http.Request, username string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "|" + clientIP(r)
}

func isLoginLocked(key string) (bool, time.Duration) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()

	state, ok := loginAttempts[key]
	if !ok {
		return false, 0
	}

	now := time.Now()
	if !state.LockedUntil.IsZero() {
		if now.Before(state.LockedUntil) {
			return true, time.Until(state.LockedUntil).Round(time.Second)
		}
		delete(loginAttempts, key)
		return false, 0
	}

	if !state.WindowStart.IsZero() && now.Sub(state.WindowStart) > loginWindow {
		delete(loginAttempts, key)
	}
	return false, 0
}

func recordLoginFailure(key string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()

	now := time.Now()
	state := loginAttempts[key]

	if !state.LockedUntil.IsZero() && now.Before(state.LockedUntil) {
		return
	}

	if state.WindowStart.IsZero() || now.Sub(state.WindowStart) > loginWindow {
		state = loginAttemptState{Failures: 1, WindowStart: now}
	} else {
		state.Failures++
	}

	if state.Failures >= loginMaxFailures {
		state.LockedUntil = now.Add(loginLockDuration)
	}

	loginAttempts[key] = state
}

func clearLoginFailures(key string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, key)
}

func startLoginAttemptsJanitor() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()

			loginAttemptsMu.Lock()
			for key, state := range loginAttempts {
				if !state.LockedUntil.IsZero() {
					if now.After(state.LockedUntil.Add(loginWindow)) {
						delete(loginAttempts, key)
					}
					continue
				}
				if !state.WindowStart.IsZero() && now.Sub(state.WindowStart) > loginWindow {
					delete(loginAttempts, key)
				}
			}
			loginAttemptsMu.Unlock()
		}
	}()
}

// (GET /api/v1/vault)
func (v *VaultServer) GetApiV1Vault(w http.ResponseWriter, r *http.Request) {
	username, ok := usernameFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var user User
	if err := DB.Where("username = ?", username).Preload("Secrets").First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	type SecretResponse struct {
		ID                    uint   `json:"id"`
		EncryptedSiteName     string `json:"encrypted_site_name"`
		SiteNameIV            string `json:"site_name_iv"`
		EncryptedSiteUsername string `json:"encrypted_site_username"`
		SiteUsernameIV        string `json:"site_username_iv"`
		EncryptedPassword     string `json:"encrypted_password"`
		IV                    string `json:"iv"`
		EncVersion            string `json:"enc_version"`
	}

	response := make([]SecretResponse, 0, len(user.Secrets))
	legacySkipped := false

	for _, s := range user.Secrets {
		if s.EncryptedSiteName == "" || s.SiteNameIV == "" ||
			s.EncryptedSiteUsername == "" || s.SiteUsernameIV == "" ||
			s.EncryptedPassword == "" || s.IV == "" {
			legacySkipped = true
			continue
		}

		encVersion := strings.TrimSpace(s.EncVersion)
		if encVersion == "" {
			encVersion = "v1"
		}

		response = append(response, SecretResponse{
			ID:                    s.ID,
			EncryptedSiteName:     s.EncryptedSiteName,
			SiteNameIV:            s.SiteNameIV,
			EncryptedSiteUsername: s.EncryptedSiteUsername,
			SiteUsernameIV:        s.SiteUsernameIV,
			EncryptedPassword:     s.EncryptedPassword,
			IV:                    s.IV,
			EncVersion:            encVersion,
		})
	}

	if legacySkipped {
		w.Header().Add("Warning", `299 - "legacy plaintext secrets omitted; migrate records"`)
	}

	writeJSON(w, http.StatusOK, response)
}

// (POST /api/v1/vault)
func (v *VaultServer) PostApiV1Vault(w http.ResponseWriter, r *http.Request) {
	var input struct {
		EncryptedSiteName     string `json:"encrypted_site_name"`
		SiteNameIV            string `json:"site_name_iv"`
		EncryptedSiteUsername string `json:"encrypted_site_username"`
		SiteUsernameIV        string `json:"site_username_iv"`
		EncryptedPassword     string `json:"encrypted_password"`
		IV                    string `json:"iv"`
		EncVersion            string `json:"enc_version"`
	}

	if err := decodeJSON(w, r, &input, maxVaultBodyBytes); err != nil {
		log.Printf("create secret decode error: %v", err)
		writeDecodeError(w, err)
		return
	}

	input.EncryptedSiteName = strings.TrimSpace(input.EncryptedSiteName)
	input.SiteNameIV = strings.TrimSpace(input.SiteNameIV)
	input.EncryptedSiteUsername = strings.TrimSpace(input.EncryptedSiteUsername)
	input.SiteUsernameIV = strings.TrimSpace(input.SiteUsernameIV)
	input.EncryptedPassword = strings.TrimSpace(input.EncryptedPassword)
	input.IV = strings.TrimSpace(input.IV)
	input.EncVersion = strings.TrimSpace(input.EncVersion)
	if input.EncVersion == "" {
		input.EncVersion = "v1"
	}

	if input.EncryptedSiteName == "" || input.SiteNameIV == "" ||
		input.EncryptedSiteUsername == "" || input.SiteUsernameIV == "" ||
		input.EncryptedPassword == "" || input.IV == "" {
		writeError(w, http.StatusBadRequest, "encrypted_site_name, site_name_iv, encrypted_site_username, site_username_iv, encrypted_password, and iv are required")
		return
	}

	if input.EncVersion != "v1" {
		writeError(w, http.StatusBadRequest, "unsupported enc_version")
		return
	}

	if !isValidCiphertext(input.EncryptedSiteName) ||
		!isValidIV(input.SiteNameIV) ||
		!isValidCiphertext(input.EncryptedSiteUsername) ||
		!isValidIV(input.SiteUsernameIV) ||
		!isValidCiphertext(input.EncryptedPassword) ||
		!isValidIV(input.IV) {
		writeError(w, http.StatusBadRequest, "invalid encrypted payload")
		return
	}

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

	newSecret := Secret{
		UserID:                user.ID,
		SiteName:              "",
		SiteUsername:          "",
		EncryptedSiteName:     input.EncryptedSiteName,
		SiteNameIV:            input.SiteNameIV,
		EncryptedSiteUsername: input.EncryptedSiteUsername,
		SiteUsernameIV:        input.SiteUsernameIV,
		EncryptedPassword:     input.EncryptedPassword,
		IV:                    input.IV,
		EncVersion:            input.EncVersion,
	}

	if err := DB.Create(&newSecret).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"message": "secret stored",
		"id":      newSecret.ID,
	})
}

// (DELETE /api/v1/vault/{id})
func (v *VaultServer) DeleteApiV1VaultId(w http.ResponseWriter, r *http.Request) {
	username, ok := usernameFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := chi.URLParam(r, "id")
	parsed, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid secret id")
		return
	}
	secretID := uint(parsed)

	var user User
	if err := DB.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	result := DB.Where("id = ? AND user_id = ?", secretID, user.ID).Delete(&Secret{})
	if result.Error != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if result.RowsAffected == 0 {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// (POST /api/v1/auth/register)
func (v *VaultServer) PostApiV1AuthRegister(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
	}

	if err := decodeJSON(w, r, &input, maxAuthBodyBytes); err != nil {
		writeDecodeError(w, err)
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	input.PasswordHash = strings.TrimSpace(input.PasswordHash)

	if input.Username == "" || input.PasswordHash == "" {
		writeError(w, http.StatusBadRequest, "username and password_hash are required")
		return
	}
	if !isValidUsername(input.Username) {
		writeError(w, http.StatusBadRequest, "username must be 3-64 chars: letters, numbers, _, ., -")
		return
	}
	if !isValidClientPasswordHash(input.PasswordHash) {
		writeError(w, http.StatusBadRequest, "invalid password_hash format")
		return
	}

	verifier, err := createPasswordVerifier(input.PasswordHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to process credentials")
		return
	}

	dbUser := User{
		Username:     input.Username,
		PasswordHash: verifier,
	}

	if err := DB.Create(&dbUser).Error; err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"message": "registration successful",
	})
}

// (POST /api/v1/auth/login)
func (v *VaultServer) PostApiV1AuthLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
	}

	if err := decodeJSON(w, r, &input, maxAuthBodyBytes); err != nil {
		writeDecodeError(w, err)
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	input.PasswordHash = strings.TrimSpace(input.PasswordHash)

	if input.Username == "" || input.PasswordHash == "" {
		writeError(w, http.StatusBadRequest, "username and password_hash are required")
		return
	}
	if !isValidUsername(input.Username) || !isValidClientPasswordHash(input.PasswordHash) {
		writeError(w, http.StatusBadRequest, "invalid credentials format")
		return
	}

	rateKey := loginRateKey(r, input.Username)
	if locked, retryIn := isLoginLocked(rateKey); locked {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many login attempts, retry in %s", retryIn))
		return
	}

	var dbUser User
	if err := DB.Where("username = ?", input.Username).First(&dbUser).Error; err != nil {
		recordLoginFailure(rateKey)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	if !verifyPasswordVerifier(input.PasswordHash, dbUser.PasswordHash) {
		recordLoginFailure(rateKey)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	clearLoginFailures(rateKey)

	if needsVerifierUpgrade(dbUser.PasswordHash) {
		if upgraded, err := createPasswordVerifier(input.PasswordHash); err == nil {
			_ = DB.Model(&dbUser).Update("password_hash", upgraded).Error
		}
	}

	token, err := GenerateJWT(dbUser.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "login successful",
		"token":   token,
	})
}

// (GET /api/v1/auth/session)
func (v *VaultServer) GetApiV1AuthSession(w http.ResponseWriter, r *http.Request) {
	username, ok := usernameFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":    true,
		"username": username,
	})
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if tokenString == "" {
			writeError(w, http.StatusUnauthorized, "missing token")
			return
		}

		claims := &Claims{}
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
		if err != nil || !token.Valid || claims.Username == "" || claims.Subject != claims.Username {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		ctx := context.WithValue(r.Context(), usernameContextKey, claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-site")

		if enableHSTS && (r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := initSecrets(); err != nil {
		fmt.Printf("❌ startup error: %v\n", err)
		os.Exit(1)
	}

	InitDB()

	if err := enforceNoLegacyPlaintextSecrets(); err != nil {
		fmt.Printf("❌ startup error: %v\n", err)
		os.Exit(1)
	}

	startLoginAttemptsJanitor()

	r := chi.NewRouter()
	r.Use(SecurityHeadersMiddleware)

	v := &VaultServer{}

	// Public
	r.Post("/api/v1/auth/register", v.PostApiV1AuthRegister)
	r.Post("/api/v1/auth/login", v.PostApiV1AuthLogin)

	// Protected
	r.With(JWTMiddleware).Get("/api/v1/auth/session", v.GetApiV1AuthSession)
	r.With(JWTMiddleware).Get("/api/v1/vault", v.GetApiV1Vault)
	r.With(JWTMiddleware).Post("/api/v1/vault", v.PostApiV1Vault)
	r.With(JWTMiddleware).Delete("/api/v1/vault/{id}", v.DeleteApiV1VaultId)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:5173", "http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         300,
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           c.Handler(r),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	fmt.Println("SecureVault API listening on :8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("❌ server error: %v\n", err)
		os.Exit(1)
	}
}
