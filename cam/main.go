package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SECRET = []byte("super-secret-demo-key")

// ===== 权限配置结构 =====

type UserConfig struct {
	Password string              `json:"password"`
	Tenant   string              `json:"tenant"`
	Roles    []string            `json:"roles"`
	Bindings map[string][]string `json:"bindings"` // node -> actions
}

type PermissionsConfig struct {
	Users map[string]UserConfig `json:"users"`
}

var permConfig PermissionsConfig

// ===== JWT Claims 结构（方便 CAG 解析） =====

type Claims struct {
	Sub    string              `json:"sub"`
	Tenant string              `json:"tenant"`
	Roles  []string            `json:"roles"`
	Perms  map[string][]string `json:"perms"`
	jwt.RegisteredClaims
}

// ===== 配置加载 =====

func loadPermissions(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("failed to open permissions config: %v", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&permConfig); err != nil {
		log.Fatalf("failed to decode permissions config: %v", err)
	}

	log.Printf("permissions loaded: %d users\n", len(permConfig.Users))
}

// ===== HTTP 处理器 =====

type LoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func login(w http.ResponseWriter, r *http.Request) {
	var req LoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}

	userCfg, ok := permConfig.Users[req.Username]
	if !ok || userCfg.Password != req.Password {
		http.Error(w, `{"error":"invalid_credentials"}`, http.StatusUnauthorized)
		return
	}

	claims := Claims{
		Sub:    req.Username,
		Tenant: userCfg.Tenant,
		Roles:  userCfg.Roles,
		Perms:  userCfg.Bindings,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := token.SignedString(SECRET)
	if err != nil {
		http.Error(w, `{"error":"token_issue_failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
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
	// 启动时加载权限配置
	loadPermissions("config/permissions.json")

	http.HandleFunc("/", home)
	http.HandleFunc("/auth/login", login)

	log.Println("CAM listening on :9000")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatal(err)
	}
}
