package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/cors"

	"github.com/go-chi/chi/v5"
	"github.com/rnz.gwb/Password-Manager/backend/api"

	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// VaultServer implements the generated api.ServerInterface
type VaultServer struct{}

// (GET /api/v1/vault)
func (v *VaultServer) GetApiV1Vault(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Returning encrypted secrets...")
}

// (POST /api/v1/vault)
func (v *VaultServer) PostApiV1Vault(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SiteName     string `json:"site_name"`
		SiteUsername string `json:"site_username"`
		Password     string `json:"password"`
	}

	// 1. Decode the JSON from the frontend
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 2. Validation
	if input.SiteName == "" || input.Password == "" {
		http.Error(w, "Site Name and Password are required", http.StatusBadRequest)
		return
	}

	// 3. Get User ID from the context (set by your JWT Middleware)
	username := r.Context().Value("username").(string)
	var user User
	DB.Where("username = ?", username).First(&user)

	// 4. Encrypt the password
	encPass, iv, err := encrypt(input.Password) // Using your AES-GCM logic
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	// 5. Create the record
	newSecret := Secret{
		UserID:            user.ID,
		SiteName:          input.SiteName,
		SiteUsername:      input.SiteUsername,
		EncryptedPassword: encPass,
		IV:                iv,
	}

	if err := DB.Create(&newSecret).Error; err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, "Secret stored successfully")
}

// (POST /api/v1/auth/register)
func (v *VaultServer) PostApiV1AuthRegister(w http.ResponseWriter, r *http.Request) {
	var newUser User

	// 1. Decode the JSON body into the 'newUser' struct
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// 2. STAGE: Validation (The fix for blank rows)
	// If the user sends empty strings or the JSON keys were wrong, we stop here.
	if newUser.Username == "" || newUser.PasswordHash == "" {
		http.Error(w, "Username and Password are required", http.StatusBadRequest)
		return
	}

	// 3. STAGE: Mapping to the Secure Struct
	// We manually transfer the validated data to our 'User' struct that has the unique index.
	dbUser := User{
		Username:     newUser.Username,
		PasswordHash: newUser.PasswordHash,
	}

	// 4. STAGE: Database Insertion
	if err := DB.Create(&dbUser).Error; err != nil {
		// Because we have 'uni_users_username' in the DB,
		// this triggers if the username already exists.
		fmt.Printf("Database insertion error: %v\n", err)
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User %s registered successfully", newUser.Username)
}

func (v *VaultServer) PostApiV1AuthLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq User
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var dbUser User
	if err := DB.Where("username = ?", loginReq.Username).First(&dbUser).Error; err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if dbUser.PasswordHash != loginReq.PasswordHash {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := GenerateJWT(dbUser.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"messsage": "Login successful",
		"token":    token,
	}
	json.NewEncoder(w).Encode(response)
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "username", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	InitDB()
	r := chi.NewRouter()

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:5173"}, // Your Vite port
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	})

	vaultHandler := &VaultServer{}
	api.HandlerFromMux(vaultHandler, r)

	r.Group(func(r chi.Router) {
		api.HandlerFromMux(vaultHandler, r)
	})

	// Protected Routes
	r.Group(func(r chi.Router) {
		r.Use(JWTMiddleware)
		// Only routes defined in your OpenAPI spec for /vault will be affected
		api.HandlerFromMux(vaultHandler, r)
	})

	fmt.Println("SecureVault API listening on :8080")
	http.ListenAndServe(":8080", c.Handler(r))
}
