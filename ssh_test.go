package sshexec

import (
	"fmt"
	"testing"
)

func TestPassword(t *testing.T) {
	resp, err := ExecPasswordAuth("127.0.0.1", 22, "root", "x", "ls -lia")
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}

func TestCert(t *testing.T) {
	pemCert := `
-----BEGIN RSA PRIVATE KEY-----
... put you PEM cert here to test
-----END RSA PRIVATE KEY-----    
    `
	resp, err := ExecCertAuth("127.0.0.1", 22, "root", pemCert, "ls -lia")
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}
