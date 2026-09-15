package main

import (
    "net/http"
    "os/exec"
)

// Intentionally unsafe: static-analysis fixture. Do not start this service.
func commandHandler(w http.ResponseWriter, r *http.Request) {
    command := r.URL.Query().Get("cmd")
    execute(command)
    _, _ = w.Write([]byte("queued"))
}

func execute(command string) {
    _ = exec.Command("sh", "-c", command).Run()
}

type LocalMux struct{}

func (m *LocalMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {}

func localHandler(w http.ResponseWriter, r *http.Request) {}

func unusedHandler(w http.ResponseWriter, r *http.Request) {}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/command", commandHandler)
    local := &LocalMux{}
    local.HandleFunc("/fake", localHandler)
    _ = http.ListenAndServe(":8080", mux)
}
