package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"io/ioutil"
)

func init() {
	directive := "keyless_server"
	caddy.RegisterPlugin(directive, caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
	httpserver.RegisterDevDirective(directive, "") //required
}

func setup(c *caddy.Controller) error {

	var signEndpoint, decryptEndpoint, privateKey string
	c.Next()
	for c.NextBlock() {
		parameter := c.Val()
		args := c.RemainingArgs()

		switch parameter {
		case "sign_endpoint":
			if len(args) != 1 {
				return c.Err("Invalid usage of sign_endpoint in keyless_server config.")
			}
			signEndpoint = c.Val()
		case "decrypt_endpoint":
			if len(args) != 1 {
				return c.Err("Invalid usage of decrypt_endpoint in keyless_server config.")
			}
			decryptEndpoint = c.Val()
		case "private_key":
			if len(args) != 1 {
				return c.Err("Invalid usage of private_key in keyless_server config.")
			}
			privateKey = c.Val()
		default:
			return c.Err("Unknown keyless_server parameter: " + parameter)
		}
	}

	if signEndpoint == "" || decryptEndpoint == "" || privateKey == "" {
		return c.Err("decrypt_endpoint, sign_endpoint, private_key can not be empty")
	}

	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return c.Err(fmt.Sprintf("parse err: %v", err))
	}
	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return keylessHandler{
			signEndpoint:    signEndpoint,
			decryptEndpoint: decryptEndpoint,
			privateKey:      key,
			rand:            rand.Reader,
			next:            next,
		}
	})
	return nil
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemFile string) (*rsa.PrivateKey, error) {
	var pemBytes []byte
	var err error

	if pemBytes, err = ioutil.ReadFile(pemFile); err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("map3: no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	default:
		return nil, fmt.Errorf("map3: unsupported key type %q", block.Type)
	}
}
