package main

import (
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
	fmt.Fprint(w, "Registering user...")
}

func main() {
	r := chi.NewRouter()

	// Initialize our server implementation
	vaultHandler := &VaultServer{}

	// This is the "Magic" line that connects your Spec to your Code
	api.HandlerFromMux(vaultHandler, r)

	fmt.Println("🛡️ SecureVault API listening on :8080")
	http.ListenAndServe(":8080", r)
}
