/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ca

import (
	"crypto"
	"crypto/elliptic"
	"fmt"

	// "crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	"github.com/pkg/errors"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/littlegirlpppp/gmsm/sm2"
)

type CA struct {
	Name               string
	Country            string
	Province           string
	Locality           string
	OrganizationalUnit string
	StreetAddress      string
	PostalCode         string
	Signer             crypto.Signer
	SignCert           *x509.Certificate
	SignSm2Cert        *sm2.Certificate
	Sm2Key             bccsp.Key
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewCA(
	baseDir,
	org,
	name,
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) (*CA, error) {

	var ca *CA

	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		return nil, err
	}
	fmt.Println("GeneratePrivateKey start ...")
	priv, err := csp.GeneratePrivateKey(baseDir)
	fmt.Println("GeneratePrivateKey end ...")
	if err != nil {
		return nil, err
	}
	sm2PubKey, err := csp.GetSM2PublicKey(priv)
	template := x509Template()
	//this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}

	//set the organization for the subject
	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
	subject.Organization = []string{org}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId =priv.SKI()

	// x509Cert, err := genCertificateECDSA(
	// 	baseDir,
	// 	name,
	// 	&template,
	// 	&template,
	// 	&priv.PublicKey,
	// 	priv,
	// )
	sm2cert := gm.ParseX509Certificate2Sm2(&template)
	sm2cert.PublicKey = sm2PubKey
	x509Cert, err := genCertificateGMSM2(baseDir, name, sm2cert, sm2cert, sm2PubKey, priv)
	if err != nil {
		return nil, err
	}
	ca = &CA{
		Name: name,
		// Signer: &csp.ECDSASigner{
		// 	PrivateKey: priv,
		// },
		// SignCert:           x509Cert,
		SignSm2Cert:        x509Cert,
		Sm2Key:             priv,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
	}

	return ca, err
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignCertificate(
	baseDir,
	name string,
	orgUnits,
	alternateNames []string,
	pub *sm2.PublicKey,
	ku x509.KeyUsage,
	eku []x509.ExtKeyUsage,
) (*sm2.Certificate, error) {

	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplateAdditional(
		ca.Country,
		ca.Province,
		ca.Locality,
		ca.OrganizationalUnit,
		ca.StreetAddress,
		ca.PostalCode,
	)
	subject.CommonName = name

	subject.OrganizationalUnit = append(subject.OrganizationalUnit, orgUnits...)

	template.Subject = subject
	for _, san := range alternateNames {
		// try to parse as an IP address first
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	// cert, err := genCertificateECDSA(
	// 	baseDir,
	// 	name,
	// 	&template,
	// 	ca.SignCert,
	// 	pub,
	// 	ca.Signer,
	// )
	template.PublicKey = pub
	sm2Tpl := gm.ParseX509Certificate2Sm2(&template)
	cert, err := genCertificateGMSM2(baseDir, name, sm2Tpl, ca.SignSm2Cert, pub, ca.Sm2Key)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

func GeneratePrivateKey(keystorePath string) (*sm2.PrivateKey, error) {

	priv, err := sm2.GenerateKey()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to generate private key")
	}

	pkcs8Encoded, err := sm2.MarshalSm2PrivateKey(priv,nil)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal private key")
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded})

	keyFile := filepath.Join(keystorePath, "priv_sk")
	err = ioutil.WriteFile(keyFile, pemEncoded, 0600)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to save private key to file %s", keyFile)
	}

	return priv, err
}
// compute Subject Key Identifier
func computeSKI(privKey *sm2.PrivateKey) []byte {
	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sha256.Sum256(raw)
	return hash[:]
}
func computeSKI1(serialise func() ([]byte, error)) ([]byte, error) {
	raw, err := serialise()
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil), nil

}

// default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

// Additional for X509 subject
func subjectTemplateAdditional(
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) pkix.Name {
	name := subjectTemplate()
	if len(country) >= 1 {
		name.Country = []string{country}
	}
	if len(province) >= 1 {
		name.Province = []string{province}
	}

	if len(locality) >= 1 {
		name.Locality = []string{locality}
	}
	if len(orgUnit) >= 1 {
		name.OrganizationalUnit = []string{orgUnit}
	}
	if len(streetAddress) >= 1 {
		name.StreetAddress = []string{streetAddress}
	}
	if len(postalCode) >= 1 {
		name.PostalCode = []string{postalCode}
	}
	return name
}

// default template for X509 certificates
func x509Template() x509.Certificate {

	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := 3650 * 24 * time.Hour
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	//basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
	}
	return x509

}

//generate a signed X509 certficate using GMSM2
func genCertificateGMSM2(baseDir, name string, template, parent *sm2.Certificate, pub *sm2.PublicKey,
	key bccsp.Key) (*sm2.Certificate, error) {
	//create the x509 public cert
	certBytes, err := gm.CreateCertificateToMem(template, parent, key)

	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	err = ioutil.WriteFile(fileName, certBytes, os.FileMode(0666))
	fmt.Println("fileName:",fileName)
	// certFile, err := os.Create(fileName)
	// if err != nil {
	// 	return nil, err
	// }

	// // pem encode the cert
	// err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	// certFile.Close()
	if err != nil {
		return nil, err
	}
	//x509Cert, err := sm2.ReadCertificateFromPem(fileName)

	x509Cert, err := sm2.ReadCertificateFromMem(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil

}

// LoadCertificateGMSM2 load a ecdsa cert from a file in cert path
func LoadCertificateGMSM2(certPath string) (*sm2.Certificate, error) {
	var cert *sm2.Certificate
	var err error

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			rawCert, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rawCert)
			cert, err = utils.DERToSM2Certificate(block.Bytes)
		}
		return nil
	}

	err = filepath.Walk(certPath, walkFunc)
	if err != nil {
		return nil, err
	}

	return cert, err
}
