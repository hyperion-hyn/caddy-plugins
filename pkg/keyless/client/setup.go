package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/caddyserver/caddy/caddytls"
	"github.com/mholt/certmagic"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	directive := "keyless_client"
	caddy.RegisterPlugin(directive, caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
	httpserver.RegisterDevDirective(directive, "") //required
}

func setup(c *caddy.Controller) error {
	tmp := c.Get("tls_custom_configs")
	if tmp == nil {
		return nil
	}
	tls := tmp.(map[string]*caddytls.Config)

	var signEndpoint, decryptEndpoint, certificate string
	c.Next() // Skip "keyless_client" literal
	for c.NextBlock() {
		parameter := c.Val()
		args := c.RemainingArgs()

		switch parameter {
		case "sign_endpoint":
			if len(args) != 1 {
				return c.Err("Invalid usage of sign_endpoint in keyless_client config.")
			}
			signEndpoint = c.Val()
		case "decrypt_endpoint":
			if len(args) != 1 {
				return c.Err("Invalid usage of decrypt_endpoint in keyless_client config.")
			}
			decryptEndpoint = c.Val()
		case "certificate":
			if len(args) != 1 {
				return c.Err("Invalid usage of certificate in keyless_client config.")
			}
			certificate = c.Val()
		default:
			return c.Err("Unknown keyless_client parameter: " + parameter)
		}
	}

	addr, err := standardizeAddress(c.Key)
	if err != nil {
		fmt.Printf("error: %s \n", err)
		return nil
	}

	config, ok := tls[addr.Host]
	if !ok {
		return nil
	}
	cert, err := loadTLSCertificate(signEndpoint, decryptEndpoint, certificate)
	if err != nil {
		return c.Errf("keyless certification generation: %v", err)
	}

	err = config.Manager.CacheUnmanagedTLSCertificate(*cert, []string{})
	if err != nil {
		return c.Errf("keyless: %v", err)
	}

	return nil
}

func standardizeAddress(str string) (httpserver.Address, error) {
	input := str

	httpPort := strconv.Itoa(certmagic.HTTPPort)
	httpsPort := strconv.Itoa(certmagic.HTTPSPort)

	// Split input into components (prepend with // to assert host by default)
	if !strings.Contains(str, "//") && !strings.HasPrefix(str, "/") {
		str = "//" + str
	}
	u, err := url.Parse(str)
	if err != nil {
		return httpserver.Address{}, err
	}

	// separate host and port
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port, err = net.SplitHostPort(u.Host + ":")
		if err != nil {
			host = u.Host
		}
	}

	// see if we can set port based off scheme
	if port == "" {
		if u.Scheme == "http" {
			port = httpPort
		} else if u.Scheme == "https" {
			port = httpsPort
		}
	}

	// repeated or conflicting scheme is confusing, so error
	if u.Scheme != "" && (port == "http" || port == "https") {
		return httpserver.Address{}, fmt.Errorf("[%s] scheme specified twice in address", input)
	}

	// error if scheme and port combination violate convention
	if (u.Scheme == "http" && port == httpsPort) || (u.Scheme == "https" && port == httpPort) {
		return httpserver.Address{}, fmt.Errorf("[%s] scheme and port violate convention", input)
	}

	// standardize http and https ports to their respective port numbers
	if port == "http" {
		u.Scheme = "http"
		port = httpPort
	} else if port == "https" {
		u.Scheme = "https"
		port = httpsPort
	}

	return httpserver.Address{Original: input, Scheme: u.Scheme, Host: host, Port: port, Path: u.Path}, err
}

/*
func loadCertificate() (*tls.Certificate, error) {
	//serverAddr := "key.tile.map3.network:5001"

	//keyserverCA, err := parseCA("./testdata/tile-ca.pem")
	//if err != nil {
	//	return nil, err
	//}
	//keyless := server.NewClient(tls.Certificate{}, keyserverCA)
	//cert, err := keyless.LoadTLSCertificate(serverAddr, "./testdata/tile-server.pem")
	cert, err := loadTLSCertificate("", "./testdata/tile-server.pem")
	return cert, err
}

func parseCA(filepath string) (*x509.CertPool, error) {
	pemCerts, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	keyserverCA := x509.NewCertPool()
	if !keyserverCA.AppendCertsFromPEM(pemCerts) {
		return nil, errors.New("gokeyless/server: failed to read keyserver CA from PEM")
	}
	return keyserverCA, nil
}
*/
func loadTLSCertificate(signEndpoint string, decryptEndpoint string, filepath string) (*tls.Certificate, error) {
	var certPEMBlock []byte
	var certDERBlock *pem.Block
	var err error
	cert := &tls.Certificate{}

	if certPEMBlock, err = ioutil.ReadFile(filepath); err != nil {
		return nil, err
	}

	for {
		if certDERBlock, certPEMBlock = pem.Decode(certPEMBlock); certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		return nil, err
	}

	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, err
	}
	//x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	//if err != nil {
	//	return nil, err
	//}
	pk := &keylessClient{
		signEndpoint:    signEndpoint,
		decryptEndpoint: decryptEndpoint,
		publicKey:       cert.Leaf.PublicKey,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
			},
			Timeout: time.Duration(30) * time.Second,
		},
	}
	cert.PrivateKey = pk
	return cert, nil
}
