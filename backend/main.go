package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rnz.gwb/Password-Manager/backend/api"
)

// VaultServer implements the generated api.ServerInterface
type VaultServer struct{}

// (GET /api/v1/vault)
func (v *VaultServer) GetApiV1Vault(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Returning encrypted secrets...")
}

// (POST /api/v1/vault)
func (v *VaultServer) PostApiV1Vault(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Storing new secret...")
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

func main() {
	InitDB()
	r := chi.NewRouter()

	// Initialize our server implementation
	vaultHandler := &VaultServer{}

	// This is the "Magic" line that connects your Spec to your Code
	api.HandlerFromMux(vaultHandler, r)

	fmt.Println("SecureVault API listening on :8080")
	http.ListenAndServe(":8080", r)
}
