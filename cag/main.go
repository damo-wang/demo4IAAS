package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    _ "github.com/go-sql-driver/mysql"
)

var SECRET = []byte("super-secret-demo-key")

var nodeMap = map[string]string{
    "node-1": "http://node-1:8080",
    "node-2": "http://node-2:8080",
}

// ==== JWT Claims ====

type Claims struct {
    Sub    string              `json:"sub"`
    Tenant string              `json:"tenant"`
    Roles  []string            `json:"roles"`
    Perms  map[string][]string `json:"perms"`
    jwt.RegisteredClaims
}

// ==== DB for audit ====

var auditDB *sql.DB

func getEnv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

func initAuditDB() {
    dbHost := getEnv("DB_HOST", "mysql")
    dbPort := getEnv("DB_PORT", "3306")
    dbUser := getEnv("DB_USER", "iamuser")
    dbPass := getEnv("DB_PASSWORD", "iampass")
    dbName := getEnv("DB_NAME", "iamdb")

    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
        dbUser, dbPass, dbHost, dbPort, dbName)

    var err error
    auditDB, err = sql.Open("mysql", dsn)
    if err != nil {
        log.Fatalf("CAG: failed to open audit db: %v", err)
    }

    for i := 0; i < 10; i++ {
        if err = auditDB.Ping(); err == nil {
            break
        }
        log.Printf("CAG: waiting for mysql... (%d/10) err=%v", i+1, err)
        time.Sleep(2 * time.Second)
    }
    if err != nil {
        log.Fatalf("CAG: failed to connect mysql: %v", err)
    }

    // 审计表
    _, err = auditDB.Exec(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id           BIGINT AUTO_INCREMENT PRIMARY KEY,
          timestamp    DATETIME NOT NULL,
          username     VARCHAR(64) NOT NULL,
          tenant       VARCHAR(64) NOT NULL,
          node         VARCHAR(64) NOT NULL,
          action       VARCHAR(64) NOT NULL,
          method       VARCHAR(16) NOT NULL,
          path         VARCHAR(255) NOT NULL,
          status_code  INT NOT NULL,
          allowed      TINYINT(1) NOT NULL,
          source_ip    VARCHAR(64) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `)
    if err != nil {
        log.Fatalf("CAG: create audit_logs failed: %v", err)
    }

    log.Println("CAG: audit DB ready")
}

// ==== JWT & 权限 ====

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

// ==== 审计写入 ====

func clientIP(r *http.Request) string {
    // 尝试从 X-Forwarded-For 取真实 IP（此处 nginx → CAG 同网，可简单用 RemoteAddr）
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        parts := strings.Split(xff, ",")
        return strings.TrimSpace(parts[0])
    }
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    return host
}

func writeAuditLog(claims *Claims, r *http.Request, node, action string, status int, allowed bool) {
    if auditDB == nil {
        return
    }

    _, err := auditDB.Exec(`
        INSERT INTO audit_logs (timestamp, username, tenant, node, action, method, path, status_code, allowed, source_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        time.Now().UTC(),
        claims.Sub,
        claims.Tenant,
        node,
        action,
        r.Method,
        r.URL.Path,
        status,
        boolToInt(allowed),
        clientIP(r),
    )
    if err != nil {
        log.Printf("CAG: failed to write audit log: %v", err)
    }
}

func boolToInt(b bool) int {
    if b {
        return 1
    }
    return 0
}

// ==== 反向代理 ====

func proxy(w http.ResponseWriter, r *http.Request, node, path string) (*http.Response, error) {
    target, ok := nodeMap[node]
    if !ok {
        return nil, fmt.Errorf("node_not_found")
    }

    if r.Method == http.MethodGet {
        return http.Get(target + path)
    }

    body, _ := io.ReadAll(r.Body)
    return http.Post(target+path, "application/json", strings.NewReader(string(body)))
}

// ==== 具体 Handler ====

func statusHandler(w http.ResponseWriter, r *http.Request) {
    node := strings.TrimPrefix(r.URL.Path, "/nodes/")
    node = strings.TrimSuffix(node, "/status")

    claims, err := verify(r)
    if err != nil {
        http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
        return
    }

    action := "status"
    if !hasPermission(claims, node, action) {
        writeAuditLog(claims, r, node, action, http.StatusForbidden, false)
        http.Error(w, `{"error":"access_denied"}`, http.StatusForbidden)
        return
    }

    resp, err := proxy(w, r, node, "/status")
    if err != nil {
        writeAuditLog(claims, r, node, action, http.StatusInternalServerError, true)
        http.Error(w, `{"error":"proxy_error"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    data, _ := io.ReadAll(resp.Body)
    writeAuditLog(claims, r, node, action, resp.StatusCode, true)

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(resp.StatusCode)
    w.Write(data)
}

func execHandler(w http.ResponseWriter, r *http.Request) {
    node := strings.TrimPrefix(r.URL.Path, "/nodes/")
    node = strings.TrimSuffix(node, "/exec")

    claims, err := verify(r)
    if err != nil {
        http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
        return
    }

    action := "exec"
    if !hasPermission(claims, node, action) {
        writeAuditLog(claims, r, node, action, http.StatusForbidden, false)
        http.Error(w, `{"error":"access_denied"}`, http.StatusForbidden)
        return
    }

    resp, err := proxy(w, r, node, "/exec")
    if err != nil {
        writeAuditLog(claims, r, node, action, http.StatusInternalServerError, true)
        http.Error(w, `{"error":"proxy_error"}`, http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    data, _ := io.ReadAll(resp.Body)
    writeAuditLog(claims, r, node, action, resp.StatusCode, true)

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(resp.StatusCode)
    w.Write(data)
}

func home(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]string{"msg": "CAG Gateway Running"})
}

func main() {
    initAuditDB()
    defer auditDB.Close()

    http.HandleFunc("/", home)
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
