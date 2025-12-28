package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"time"
)

type Status struct {
	Node     string  `json:"node"`
	CPUUsage float64 `json:"cpu_usage"`
	MEMUsage float64 `json:"mem_usage"`
}

type ExecReq struct {
	Cmd string `json:"cmd"`
}

type ExecResp struct {
	Node   string `json:"node"`
	Cmd    string `json:"cmd"`
	Result string `json:"result"`
	Status string `json:"status"`
}

var nodeName = "unknown-node"

func statusHandler(w http.ResponseWriter, r *http.Request) {
	resp := Status{
		Node:     nodeName,
		CPUUsage: float64(rand.Intn(80)+10) / 100,
		MEMUsage: float64(rand.Intn(80)+10) / 100,
	}
	json.NewEncoder(w).Encode(resp)
}

func execHandler(w http.ResponseWriter, r *http.Request) {
	var req ExecReq
	json.NewDecoder(r.Body).Decode(&req)

	resp := ExecResp{
		Node:   nodeName,
		Cmd:    req.Cmd,
		Result: "simulated result of `" + req.Cmd + "`",
		Status: "ok",
	}
	json.NewEncoder(w).Encode(resp)
}

func root(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"msg": "Node Agent running on " + nodeName})
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if n := os.Getenv("NODE_NAME"); n != "" {
		nodeName = n
	}

	http.HandleFunc("/", root)
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/exec", execHandler)

	http.ListenAndServe(":8080", nil)
}
