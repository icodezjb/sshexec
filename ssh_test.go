package sshexec

import (
	"fmt"
	"testing"
)

func TestPassword(t *testing.T) {
	sshExec, err := NewPasswordAuth("127.0.0.1", 22, "root", "x")
	if err != nil {
		panic(err)
	}

	resp, err := sshExec.Exec("ls -lia")
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

	sshExec, err := NewSshExecCertAuth("127.0.0.1", 22, "root", pemCert)
	if err != nil {
		panic(err)
	}

	resp, err := sshExec.Exec("ls -lia")
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}
