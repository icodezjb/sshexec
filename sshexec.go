package sshexec

import (
	"bytes"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func ExecPasswordAuth(host string, port int, user string, password string, command string) (string, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
	}
	client, err := ssh.Dial("tcp", host+":"+strconv.Itoa(port), config)
	if err != nil {
		return "", err
	}

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run(command); err != nil {
		return "", err
	}
	return b.String(), nil
}

func ExecCertAuth(host string, port int, user string, pemCert string, command string) (string, error) {
	signer, err := ssh.ParsePrivateKey([]byte(pemCert))
	if err != nil {
		return "", err
	}

	config := &ssh.ClientConfig{
		User: "ubuntu",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}
	client, err := ssh.Dial("tcp", host+":"+strconv.Itoa(port), config)
	if err != nil {
		return "", err
	}

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run(command); err != nil {
		return "", err
	}
	return b.String(), nil
}
