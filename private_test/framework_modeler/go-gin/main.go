package main

import (
    "net/http"
    "os/exec"

    "github.com/gin-gonic/gin"
)

// Intentionally unsafe: static-analysis fixture. Do not start this service.
func commandHandler(c *gin.Context) {
    command := c.Query("cmd")
    execute(command)
    c.String(http.StatusOK, "queued")
}

func execute(command string) {
    _ = exec.Command("sh", "-c", command).Run()
}

type LocalRouter struct{}

func (r *LocalRouter) GET(path string, handler func(*gin.Context)) {}

func localHandler(c *gin.Context) {
    // Signature alone is not evidence of a registered HTTP route.
}

func unusedHandler(c *gin.Context) {}

func main() {
    router := gin.Default()
    router.GET("/command", commandHandler)
    local := &LocalRouter{}
    local.GET("/fake", localHandler)
    _ = router.Run(":8080")
}
