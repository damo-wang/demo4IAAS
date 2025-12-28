package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SECRET = []byte("super-secret-demo-key")

var nodeMap = map[string]string{
	"node-1": "http://node-1:8080",
	"node-2": "http://node-2:8080",
}

func verify(r *http.Request) (jwt.MapClaims, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, fmt.Errorf("missing token")
	}

	tokenStr := strings.TrimPrefix(h, "Bearer ")
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return SECRET, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token.Claims.(jwt.MapClaims), nil
}

func contains(arr []any, v string) bool {
	for _, x := range arr {
		if x.(string) == v {
			return true
		}
	}
	return false
}

func proxy(w http.ResponseWriter, r *http.Request, node string, path string) {
	target, ok := nodeMap[node]
	if !ok {
		http.Error(w, `{"error":"node_not_found"}`, 404)
		return
	}

	var resp *http.Response
	var err error

	if r.Method == "GET" {
		resp, err = http.Get(target + path)
	} else {
		body, _ := io.ReadAll(r.Body)
		resp, err = http.Post(target+path, "application/json", strings.NewReader(string(body)))
	}

	if err != nil {
		http.Error(w, `{"error":"proxy_error"}`, 500)
		return
	}

	logAccess(r, node, path, resp.StatusCode)

	data, _ := io.ReadAll(resp.Body)
	w.Write(data)
}

func status(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimPrefix(r.URL.Path, "/nodes/")
	node = strings.TrimSuffix(node, "/status")

	claims, err := verify(r)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}

	if !contains(claims["allowed_nodes"].([]any), node) {
		http.Error(w, `{"error":"access_denied"}`, 403)
		return
	}

	proxy(w, r, node, "/status")
}

func exec(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimPrefix(r.URL.Path, "/nodes/")
	node = strings.TrimSuffix(node, "/exec")

	claims, err := verify(r)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}

	if !contains(claims["allowed_nodes"].([]any), node) {
		http.Error(w, `{"error":"access_denied"}`, 403)
		return
	}

	proxy(w, r, node, "/exec")
}

func logAccess(r *http.Request, node, action string, status int) {
	fmt.Println("==== AUDIT LOG ====")
	fmt.Println("time:", time.Now().UTC())
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
	http.HandleFunc("/nodes/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			status(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/exec") {
			exec(w, r)
		} else {
			http.NotFound(w, r)
		}
	})

	http.ListenAndServe(":8000", nil)
}
