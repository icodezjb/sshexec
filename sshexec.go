package sshexec

import (
	"bytes"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type Exec interface {
	Exec(command string) (string, error)
}

func NewPasswordAuth(host string, port int, user string, password string) (*SshExecPasswordAuth, error) {
	return &SshExecPasswordAuth{host: host, port: port, user: user, password: password}, nil
}

type SshExecPasswordAuth struct {
	host     string
	port     int
	user     string
	password string
}

func (s *SshExecPasswordAuth) Exec(command string) (string, error) {
	config := &ssh.ClientConfig{
		User: s.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", s.host+":"+strconv.Itoa(s.port), config)
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

type SshExecCertAuth struct {
	host    string
	port    int
	user    string
	pemCert string
}

func NewSshExecCertAuth(host string, port int, user string, pemCert string) (*SshExecCertAuth, error) {
	return &SshExecCertAuth{host: host, port: port, user: user, pemCert: pemCert}, nil
}

func (s *SshExecCertAuth) Exec(command string) (string, error) {
	signer, err := ssh.ParsePrivateKey([]byte(s.pemCert))
	if err != nil {
		return "", err
	}

	config := &ssh.ClientConfig{
		User: s.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", s.host+":"+strconv.Itoa(s.port), config)
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
