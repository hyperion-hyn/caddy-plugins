package server

import (
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"io"
	"io/ioutil"
	"net/http"
)

type keylessHandler struct {
	signEndpoint    string
	decryptEndpoint string
	privateKey      *rsa.PrivateKey //crypto.PrivateKey
	next            httpserver.Handler
	rand            io.Reader
}

type RequestBody struct {
	Hash uint64 `json:"hash"`
	Msg  string `json:"msg"`
}

var rsaCrypto = map[uint64]crypto.Hash{
	1: crypto.MD5SHA1,
	2: crypto.SHA1,
	3: crypto.SHA224,
	4: crypto.SHA256,
	5: crypto.SHA384,
	6: crypto.SHA512,
}

func (h keylessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	urlPath := r.URL.Path
	//match := false
	//if !httpserver.Path(urlPath).Matches(p)
	if r.Method != http.MethodPost || (urlPath != h.signEndpoint && urlPath != h.decryptEndpoint) {
		return h.next.ServeHTTP(w, r)
	}
	if urlPath == h.signEndpoint {
		return h.singRequest(w, r)
	} else {
		//TODO	decrypt request
		return 200, nil
	}
}

func (h keylessHandler) singRequest(w http.ResponseWriter, r *http.Request) (int, error) {
	var (
		bodyBytes []byte
		digest    []byte
		err       error
		body      *RequestBody
	)
	if bodyBytes, err = ioutil.ReadAll(r.Body); err != nil {
		return http.StatusInternalServerError, errors.New("read body error")
	} else if err = json.Unmarshal(bodyBytes, &body); err != nil {
		return http.StatusInternalServerError, errors.New("parse body error")
	} else if _, ok := rsaCrypto[body.Hash]; !ok {
		return http.StatusBadRequest, errors.New("not support hash func")
	}
	if digest, err = hex.DecodeString(body.Msg); err != nil {
		return http.StatusBadRequest, errors.New("decode error")
	}

	if bodyBytes, err = h.privateKey.Sign(h.rand, digest, rsaCrypto[body.Hash]); err != nil {
		return http.StatusInternalServerError, errors.New("sign error")
	}
	if _, err := w.Write(bodyBytes); err != nil {
		fmt.Printf("%v \n", err)
		return http.StatusInternalServerError, errors.New("unable to write body")
	}
	return 200, nil
}
