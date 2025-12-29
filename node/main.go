package main

import (
    "encoding/json"
    "log"
    "net/http"
    "os"
    "time"
)

type ExecRequest struct {
    Cmd string `json:"cmd"`
}

type StatusResponse struct {
    Node      string    `json:"node"`
    Status    string    `json:"status"`
    Timestamp time.Time `json:"timestamp"`
}

type ExecResponse struct {
    Node      string    `json:"node"`
    Executed  bool      `json:"executed"`
    Cmd       string    `json:"cmd"`
    Timestamp time.Time `json:"timestamp"`
}

func getEnv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
    nodeName := getEnv("NODE_NAME", "node-1")

    resp := StatusResponse{
        Node:      nodeName,
        Status:    "ok",
        Timestamp: time.Now().UTC(),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

func execHandler(w http.ResponseWriter, r *http.Request) {
    nodeName := getEnv("NODE_NAME", "node-1")

    var req ExecRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
        return
    }

    // Demo：不真正执行命令，只是 echo 回去
    resp := ExecResponse{
        Node:      nodeName,
        Executed:  true,
        Cmd:       req.Cmd,
        Timestamp: time.Now().UTC(),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

func main() {
    http.HandleFunc("/status", statusHandler)
    http.HandleFunc("/exec", execHandler)

    port := getEnv("NODE_HTTP_PORT", "8080")
    log.Printf("Node [%s] listening on :%s\n", getEnv("NODE_NAME", "node-1"), port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatal(err)
    }
}
