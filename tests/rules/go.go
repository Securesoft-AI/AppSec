package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	id := r.URL.Query().Get("id")
	// ruleid: go-sql-injection
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	// ok: go-sql-injection
	db.Query("SELECT * FROM users WHERE id = $1", id)

	host := r.FormValue("host")
	// ruleid: go-command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ok: go-command-injection
	exec.Command("uptime").Run()

	target := r.URL.Query().Get("url")
	// ruleid: go-ssrf
	http.Get(target)
	// ok: go-ssrf
	http.Get("https://api.example.com/status")

	name := r.URL.Query().Get("file")
	// ruleid: go-path-traversal
	os.ReadFile("/srv/data/" + name)
	// ok: go-path-traversal
	os.ReadFile(filepath.Join("/srv/data", filepath.Base(name)))
}

func client() *http.Client {
	// ruleid: go-tls-insecure-skip-verify
	cfg := &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func hashes(b []byte) {
	// ruleid: go-weak-crypto
	md5.Sum(b)
	// ok: go-weak-crypto
	sha256.Sum256(b)
}
