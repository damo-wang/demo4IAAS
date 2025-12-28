package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SECRET = []byte("super-secret-demo-key")

type User struct {
	Password     string
	Tenant       string
	Roles        []string
	AllowedNodes []string
}

var users = map[string]User{
	"alice": {Password: "123456", Tenant: "tenant-1", Roles: []string{"ops"}, AllowedNodes: []string{"node-1", "node-2"}},
	"bob":   {Password: "123456", Tenant: "tenant-2", Roles: []string{"viewer"}, AllowedNodes: []string{"node-2"}},
}

type LoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func login(w http.ResponseWriter, r *http.Request) {
	var req LoginReq
	json.NewDecoder(r.Body).Decode(&req)

	user, ok := users[req.Username]
	if !ok || user.Password != req.Password {
		http.Error(w, `{"error":"invalid_credentials"}`, 401)
		return
	}

	claims := jwt.MapClaims{
		"sub":           req.Username,
		"tenant":        user.Tenant,
		"roles":         user.Roles,
		"allowed_nodes": user.AllowedNodes,
		"exp":           time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, _ := token.SignedString(SECRET)

	json.NewEncoder(w).Encode(map[string]any{
		"access_token": str,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func home(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"msg": "CAM Service Running"})
}

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/auth/login", login)

	http.ListenAndServe(":9000", nil)
}
