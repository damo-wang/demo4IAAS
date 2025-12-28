package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/golang-jwt/jwt/v5"
    _ "github.com/go-sql-driver/mysql"
)

var SECRET = []byte("super-secret-demo-key") // demo 用，生产应更安全管理

var db *sql.DB

type Claims struct {
    Sub    string              `json:"sub"`
    Tenant string              `json:"tenant"`
    Roles  []string            `json:"roles"`
    Perms  map[string][]string `json:"perms"` // node -> actions
    jwt.RegisteredClaims
}

type LoginReq struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type UserInfo struct {
    ID       int
    Username string
    Password string
    Tenant   string
}

func getEnv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

// 初始化 MySQL 连接
func initDB() {
    dbHost := getEnv("DB_HOST", "mysql")
    dbPort := getEnv("DB_PORT", "3306")
    dbUser := getEnv("DB_USER", "iamuser")
    dbPass := getEnv("DB_PASSWORD", "iampass")
    dbName := getEnv("DB_NAME", "iamdb")

    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
        dbUser, dbPass, dbHost, dbPort, dbName)

    var err error
    db, err = sql.Open("mysql", dsn)
    if err != nil {
        log.Fatalf("failed to open db: %v", err)
    }

    // 简单重试，等待 MySQL 就绪
    for i := 0; i < 10; i++ {
        err = db.Ping()
        if err == nil {
            break
        }
        log.Printf("waiting for mysql... (%d/10) err=%v\n", i+1, err)
        time.Sleep(2 * time.Second)
    }
    if err != nil {
        log.Fatalf("failed to connect mysql: %v", err)
    }

    log.Println("connected to mysql")

    createSchema()
    seedDemoData()
}

// 建表
func createSchema() {
    stmts := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL UNIQUE,
            password VARCHAR(128) NOT NULL,
            tenant   VARCHAR(64) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

        `CREATE TABLE IF NOT EXISTS roles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL UNIQUE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

        `CREATE TABLE IF NOT EXISTS user_roles (
            user_id INT NOT NULL,
            role_id INT NOT NULL,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

        `CREATE TABLE IF NOT EXISTS nodes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name   VARCHAR(64) NOT NULL UNIQUE,
            tenant VARCHAR(64) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

        `CREATE TABLE IF NOT EXISTS permissions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            action VARCHAR(64) NOT NULL UNIQUE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

        `CREATE TABLE IF NOT EXISTS role_node_permissions (
            role_id INT NOT NULL,
            node_id INT NOT NULL,
            perm_id INT NOT NULL,
            PRIMARY KEY (role_id, node_id, perm_id),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
            FOREIGN KEY (perm_id) REFERENCES permissions(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,
    }

    for _, s := range stmts {
        if _, err := db.Exec(s); err != nil {
            log.Fatalf("failed to exec schema: %v", err)
        }
    }

    log.Println("schema ensured")
}

// 初始化 demo 权限数据
func seedDemoData() {
    var count int
    if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
        log.Fatalf("failed to count users: %v", err)
    }
    if count > 0 {
        log.Println("demo data already exists")
        return
    }

    log.Println("seeding demo data...")

    _, err := db.Exec(`
        INSERT INTO users (username, password, tenant) VALUES
        ('alice', '123456', 'tenant-1'),
        ('bob',   '123456', 'tenant-2');
    `)
    if err != nil {
        log.Fatalf("failed to seed users: %v", err)
    }

    _, err = db.Exec(`
        INSERT INTO roles (name) VALUES
        ('ops'),
        ('viewer');
    `)
    if err != nil {
        log.Fatalf("failed to seed roles: %v", err)
    }

    _, err = db.Exec(`
        INSERT INTO nodes (name, tenant) VALUES
        ('node-1', 'tenant-1'),
        ('node-2', 'tenant-1');
    `)
    if err != nil {
        log.Fatalf("failed to seed nodes: %v", err)
    }

    _, err = db.Exec(`
        INSERT INTO permissions (action) VALUES
        ('status'),
        ('exec');
    `)
    if err != nil {
        log.Fatalf("failed to seed permissions: %v", err)
    }

    // user_roles
    _, err = db.Exec(`
        INSERT INTO user_roles (user_id, role_id)
        SELECT u.id, r.id FROM users u, roles r
        WHERE (u.username='alice' AND r.name='ops')
           OR (u.username='bob'   AND r.name='viewer');
    `)
    if err != nil {
        log.Fatalf("failed to seed user_roles: %v", err)
    }

    // role_node_permissions
    // alice(ops): node-1(status, exec), node-2(status)
    _, err = db.Exec(`
        INSERT INTO role_node_permissions (role_id, node_id, perm_id)
        SELECT r.id, n.id, p.id
        FROM roles r, nodes n, permissions p
        WHERE r.name='ops' AND n.name='node-1' AND p.action IN ('status','exec');
    `)
    if err != nil {
        log.Fatalf("failed to seed rnp (ops/node-1): %v", err)
    }

    _, err = db.Exec(`
        INSERT INTO role_node_permissions (role_id, node_id, perm_id)
        SELECT r.id, n.id, p.id
        FROM roles r, nodes n, permissions p
        WHERE r.name='ops' AND n.name='node-2' AND p.action='status';
    `)
    if err != nil {
        log.Fatalf("failed to seed rnp (ops/node-2): %v", err)
    }

    // bob(viewer): node-2(status)
    _, err = db.Exec(`
        INSERT INTO role_node_permissions (role_id, node_id, perm_id)
        SELECT r.id, n.id, p.id
        FROM roles r, nodes n, permissions p
        WHERE r.name='viewer' AND n.name='node-2' AND p.action='status';
    `)
    if err != nil {
        log.Fatalf("failed to seed rnp (viewer/node-2): %v", err)
    }

    log.Println("demo data seeded")
}

func getUserByUsername(username string) (*UserInfo, error) {
    row := db.QueryRow(`SELECT id, username, password, tenant FROM users WHERE username = ?`, username)
    var u UserInfo
    if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Tenant); err != nil {
        return nil, err
    }
    return &u, nil
}

func getUserRoles(userID int) ([]string, error) {
    rows, err := db.Query(`
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = ?`, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var roles []string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            return nil, err
        }
        roles = append(roles, name)
    }
    return roles, nil
}

func getUserPermissions(userID int) (map[string][]string, error) {
    rows, err := db.Query(`
        SELECT n.name, p.action
        FROM users u
        JOIN user_roles ur ON ur.user_id = u.id
        JOIN roles r ON r.id = ur.role_id
        JOIN role_node_permissions rnp ON rnp.role_id = r.id
        JOIN nodes n ON n.id = rnp.node_id
        JOIN permissions p ON p.id = rnp.perm_id
        WHERE u.id = ?`, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    perms := make(map[string][]string)
    for rows.Next() {
        var nodeName, action string
        if err := rows.Scan(&nodeName, &action); err != nil {
            return nil, err
        }
        perms[nodeName] = append(perms[nodeName], action)
    }
    return perms, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var req LoginReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
        return
    }

    user, err := getUserByUsername(req.Username)
    if err != nil || user.Password != req.Password {
        http.Error(w, `{"error":"invalid_credentials"}`, http.StatusUnauthorized)
        return
    }

    roles, err := getUserRoles(user.ID)
    if err != nil {
        http.Error(w, `{"error":"role_query_failed"}`, http.StatusInternalServerError)
        return
    }

    perms, err := getUserPermissions(user.ID)
    if err != nil {
        http.Error(w, `{"error":"perm_query_failed"}`, http.StatusInternalServerError)
        return
    }

    claims := Claims{
        Sub:    user.Username,
        Tenant: user.Tenant,
        Roles:  roles,
        Perms:  perms,
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

func homeHandler(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]string{"msg": "CAM Service Running"})
}

func main() {
    initDB()
    defer db.Close()

    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/auth/login", loginHandler)

    log.Println("CAM listening on :9000")
    if err := http.ListenAndServe(":9000", nil); err != nil {
        log.Fatal(err)
    }
}
