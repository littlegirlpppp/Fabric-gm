/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp

import (
	"crypto"
	"crypto/ecdsa"

	// "crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	//todo：国密：sm2
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	// "github.com/hyperledger/fabric/bccsp/utils"
	"github.com/littlegirlpppp/gmsm/sm2"
	gmx509 "github.com/littlegirlpppp/gmsm/x509"
)

// LoadPrivateKey loads a private key from a file in keystorePath.  It looks
// for a file ending in "_sk" and expects a PEM-encoded PKCS8 EC private key.
// func LoadPrivateKey(keystorePath string) (*ecdsa.PrivateKey, error) {
func LoadPrivateKey(keystorePath string) (bccsp.Key, error) {
	// var priv *ecdsa.PrivateKey
	var priv bccsp.Key

	walkFunc := func(path string, info os.FileInfo, pathErr error) error {

		if !strings.HasSuffix(path, "_sk") {
			return nil
		}

		rawKey, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		priv, err = parsePrivateKeyPEM(rawKey, path)
		if err != nil {
			return errors.WithMessage(err, path)
		}

		return nil
	}

	err := filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		return nil, err
	}

	return priv, err
}

// func parsePrivateKeyPEM(rawKey []byte) (*ecdsa.PrivateKey, error) {
func parsePrivateKeyPEM(rawKey []byte, path string) (bccsp.Key, error) {
	opts := &factory.FactoryOpts{
		//todo：国密：sm3 opt
		ProviderName: "GM",
		SwOpts: &factory.SwOpts{
			HashFamily: "GMSM3",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: path,
			},
		},
	}

	csp, err0 := factory.GetBCCSPFromOpts(opts)
	if err0 != nil {
		return nil, err0
	}

	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, errors.New("bytes are not PEM encoded")
	}

	// key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	priv, err := csp.KeyImport(block.Bytes, &bccsp.GMSM2PrivateKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, errors.WithMessage(err, "pem bytes are not PKCS8 encoded ")
	}

	// priv, ok := key.(*ecdsa.PrivateKey)
	// if !ok {
	// 	return nil, errors.New("pem bytes do not contain an EC private key")
	// }
	return priv, nil
}

// GeneratePrivateKey creates an EC private key using a P-256 curve and stores
// it in keystorePath.
// func GeneratePrivateKey(keystorePath string) (*ecdsa.PrivateKey, error) {
func GeneratePrivateKey(keystorePath string) (bccsp.Key, error) {

	opts := &factory.FactoryOpts{
		//todo：国密：sm3 opt
		ProviderName: "GM",
		SwOpts: &factory.SwOpts{
			HashFamily: "GMSM3",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
	}
	csp, err0 := factory.GetBCCSPFromOpts(opts)
	if err0 != nil {
		return nil, err0
	}
	// priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, err := csp.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false}) 
	if err != nil {
		return nil, errors.WithMessage(err, "failed to generate private key")
	}

	// pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	// pkcs8Encoded, err := sm2.MarshalSm2UnecryptedPrivateKey(priv)
	// k, err:= utils.PrivateKeyToPEM(priv, nil)
	// sm2.WritePrivateKeytoMem(k, nil)

	// if err != nil {
	// 	return nil, errors.WithMessage(err, "failed to marshal private key")
	// }

	// pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded})

	// keyFile := filepath.Join(keystorePath, "priv_sk")
	// err = ioutil.WriteFile(keyFile, pemEncoded, 0600)
	// if err != nil {
	// 	return nil, errors.WithMessagef(err, "failed to save private key to file %s", keyFile)
	// }

	return priv, err
}

/**
ECDSA signer implements the crypto.Signer interface for ECDSA keys.  The
Sign method ensures signatures are created with Low S values since Fabric
normalizes all signatures to Low S.
See https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
for more detail.
*/
type ECDSASigner struct {
	PrivateKey *ecdsa.PrivateKey
}

// Public returns the ecdsa.PublicKey associated with PrivateKey.
func (e *ECDSASigner) Public() crypto.PublicKey {
	return &e.PrivateKey.PublicKey
}

// Sign signs the digest and ensures that signatures use the Low S value.
func (e *ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, e.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	// ensure Low S signatures
	sig := toLowS(
		e.PrivateKey.PublicKey,
		ECDSASignature{
			R: r,
			S: s,
		},
	)

	// return marshaled aignature
	return asn1.Marshal(sig)
}

/**
When using ECDSA, both (r,s) and (r, -s mod n) are valid signatures.  In order
to protect against signature malleability attacks, Fabric normalizes all
signatures to a canonical form where s is at most half the order of the curve.
In order to make signatures compliant with what Fabric expects, toLowS creates
signatures in this canonical form.
*/
func toLowS(key ecdsa.PublicKey, sig ECDSASignature) ECDSASignature {
	// calculate half order of the curve
	halfOrder := new(big.Int).Div(key.Curve.Params().N, big.NewInt(2))
	// check if s is greater than half order of curve
	if sig.S.Cmp(halfOrder) == 1 {
		// Set s to N - s so that s will be less than or equal to half order
		sig.S.Sub(key.Params().N, sig.S)
	}
	return sig
}

type ECDSASignature struct {
	R, S *big.Int
}

//todo：国密：sm2
func GetSM2PublicKey(priv bccsp.Key) (*sm2.PublicKey, error) {

	// get the public key
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}

	// marshal to bytes
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}
	// unmarshal using pkix
	sm2PubKey, err := gmx509.ParseSm2PublicKey(pubKeyBytes)
	//ecPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return sm2PubKey, nil
}
