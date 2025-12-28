package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SECRET = []byte("super-secret-demo-key")

// Node 映射依然是 node 名称 -> 对应的服务地址
var nodeMap = map[string]string{
	"node-1": "http://node-1:8080",
	"node-2": "http://node-2:8080",
}

// 与 CAM 中保持同样结构，方便解析
type Claims struct {
	Sub    string              `json:"sub"`
	Tenant string              `json:"tenant"`
	Roles  []string            `json:"roles"`
	Perms  map[string][]string `json:"perms"`
	jwt.RegisteredClaims
}

// 解析并验证 JWT
func verify(r *http.Request) (*Claims, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, fmt.Errorf("missing token")
	}

	tokenStr := strings.TrimPrefix(h, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return SECRET, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}
	return claims, nil
}

// 检查某个 node + action 是否被允许
func hasPermission(c *Claims, node, action string) bool {
	actions, ok := c.Perms[node]
	if !ok {
		return false
	}
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}

// 统一的代理逻辑
func proxy(w http.ResponseWriter, r *http.Request, node, path string) {
	target, ok := nodeMap[node]
	if !ok {
		http.Error(w, `{"error":"node_not_found"}`, http.StatusNotFound)
		return
	}

	var resp *http.Response
	var err error

	if r.Method == http.MethodGet {
		resp, err = http.Get(target + path)
	} else {
		body, _ := io.ReadAll(r.Body)
		resp, err = http.Post(target+path, "application/json", strings.NewReader(string(body)))
	}

	if err != nil {
		http.Error(w, `{"error":"proxy_error"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	logAccess(r, node, path, resp.StatusCode)

	data, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(data)
}

// /nodes/<node>/status
func statusHandler(w http.ResponseWriter, r *http.Request) {
	// 提取 node id
	node := strings.TrimPrefix(r.URL.Path, "/nodes/")
	node = strings.TrimSuffix(node, "/status")

	claims, err := verify(r)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if !hasPermission(claims, node, "status") {
		http.Error(w, `{"error":"access_denied"}`, http.StatusForbidden)
		return
	}

	proxy(w, r, node, "/status")
}

// /nodes/<node>/exec
func execHandler(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimPrefix(r.URL.Path, "/nodes/")
	node = strings.TrimSuffix(node, "/exec")

	claims, err := verify(r)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if !hasPermission(claims, node, "exec") {
		http.Error(w, `{"error":"access_denied"}`, http.StatusForbidden)
		return
	}

	proxy(w, r, node, "/exec")
}

func logAccess(r *http.Request, node, action string, status int) {
	fmt.Println("==== AUDIT LOG ====")
	fmt.Println("time:", time.Now().UTC())
	fmt.Println("method:", r.Method)
	fmt.Println("path:", r.URL.Path)
	fmt.Println("node:", node)
	fmt.Println("action:", action)
	fmt.Println("status:", status)
	fmt.Println("====================")
}

func home(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"msg": "CAG Gateway Running"})
}

func main() {
	http.HandleFunc("/", home)

	// 路由调度：根据 URL 后缀分发到不同 handler
	http.HandleFunc("/nodes/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodGet {
			statusHandler(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == http.MethodPost {
			execHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})

	log.Println("CAG listening on :8000")
	if err := http.ListenAndServe(":8000", nil); err != nil {
		log.Fatal(err)
	}
}
