package main

import (
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("SecureVault Backend starting on port :8080...")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Vault is Online")
	})
	http.ListenAndServe(":8080", nil)

}