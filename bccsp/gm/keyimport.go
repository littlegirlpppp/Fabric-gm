/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/littlegirlpppp/gmsm/sm2"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
	gmx509 "github.com/littlegirlpppp/gmsm/x509"
)
//todo：国密：增加gm
//实现内部的 KeyImporter 接口
type gmsm4ImportKeyOptsKeyImporter struct{}

func (*gmsm4ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if sm4Raw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &gmsm4PrivateKey{utils.Clone(sm4Raw), false}, nil
}

type gmsm2PrivateKeyImportOptsKeyImporter struct{}

func (*gmsm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {

	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}


	gmsm2SK, err := gmx509.ParsePKCS8UnecryptedPrivateKey(der)

	if err != nil {
		return nil, fmt.Errorf("Failed converting to GMSM2 private key [%s]", err)
	}

	return &gmsm2PrivateKey{gmsm2SK}, nil
}

type gmsm2PublicKeyImportOptsKeyImporter struct{}

func (*gmsm2PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[GMSM2PublicKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[GMSM2PublicKeyImportOpts] Invalid raw. It must not be nil.")
	}



	gmsm2SK, err := gmx509.ParseSm2PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting to GMSM2 public key [%s]", err)
	}

	return &gmsm2PublicKey{gmsm2SK}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *impl
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
	}

	return &ecdsaPrivateKey{ecdsaSK}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
	}

	return &ecdsaPublicKey{ecdsaPK}, nil
}

func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {

	sm2Cert, ok := raw.(*gmx509.Certificate)
	if !ok {
		cert, ok := raw.(*x509.Certificate)
		if !ok {
			return nil, errors.New("Invalid raw material. Expected *x509GM.Certificate.")
		}
		sm2Cert = ParseX509Certificate2Sm2(cert)
	}

	pk := sm2Cert.PublicKey
	switch pk.(type) {
	case sm2.PublicKey:
		fmt.Printf("bccsp gm keyimport pk is sm2.PublicKey")
		sm2PublickKey, ok := pk.(sm2.PublicKey)
		if !ok {
			return nil, errors.New("Parse interface []  to sm2 pk error")
		}
		der, err := gmx509.MarshalSm2PublicKey(&sm2PublickKey)
		if err != nil {
			return nil, errors.New("MarshalSm2PublicKey error")
		}

		return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.GMSM2PublicKeyImportOpts{})].KeyImport(
			der,
			&bccsp.GMSM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *sm2.PublicKey:
		//fmt.Printf("bccsp gm keyimport pk is *sm2.PublicKey\n")
		sm2PublickKey, ok := pk.(*sm2.PublicKey)
		if !ok {
			return nil, errors.New("Parse interface []  to sm2 pk error")
		}
		der, err := gmx509.MarshalSm2PublicKey(sm2PublickKey)
		if err != nil {
			return nil, errors.New("MarshalSm2PublicKey error")
		}
		return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.GMSM2PublicKeyImportOpts{})].KeyImport(
			der,
			&bccsp.GMSM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *ecdsa.PublicKey:
		return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [GMSM2]")
	}
}
