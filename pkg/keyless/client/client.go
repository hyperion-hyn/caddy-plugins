package client

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

var rsaCrypto = map[crypto.Hash]uint8{
	crypto.MD5SHA1: 1,
	crypto.SHA1:    2,
	crypto.SHA224:  3,
	crypto.SHA256:  4,
	crypto.SHA384:  5,
	crypto.SHA512:  6,
}

type keylessClient struct {
	signEndpoint    string
	decryptEndpoint string
	publicKey       crypto.PublicKey
	client          *http.Client
}

func (c *keylessClient) Public() crypto.PublicKey {
	return c.publicKey
}

func (c *keylessClient) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != 0 && len(msg) != opts.HashFunc().Size() {
		return nil, errors.New("input must be hashed message")
	}

	var hashFunc uint8
	switch c.Public().(type) {
	case *rsa.PublicKey:
		if value, ok := rsaCrypto[opts.HashFunc()]; ok {
			hashFunc = value
		} else {
			return nil, fmt.Errorf("unsupported hash func %v", opts.HashFunc())
		}
	//TODO support more key type: ecdsa.PublicKey
	default:
		return nil, fmt.Errorf("unsupported key type %t", c.Public())
	}

	hx := hex.EncodeToString(msg)
	rBody := map[string]interface{}{
		"hash": hashFunc,
		"msg":  hx,
	}
	bodyBytes, err := json.Marshal(rBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(c.signEndpoint, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	} else if respBytes, err := ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	} else {
		return respBytes, nil
	}
	//a, err := pk.Sign(r, msg, opts)
}

func (c *keylessClient) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	//TODO support decrypt
	println("not support")
	return nil, nil
}
