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
	var newUser api.UserAuth

	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if newUser.Username == "" || newUser.PasswordHash == "" {
		http.Error(w, "Username and password hash are required", http.StatusBadRequest)
		return
	}

	result := DB.Create(&newUser)
	if result.Error != nil {
		http.Error(w, "User already exists or database error", http.StatusConflict)
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
