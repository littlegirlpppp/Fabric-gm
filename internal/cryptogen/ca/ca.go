/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ca

import (
	"crypto"
	"fmt"

	// "crypto/elliptic"
	"crypto/rand"
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

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	"github.com/littlegirlpppp/gmsm/sm2"
	gmx509 "github.com/littlegirlpppp/gmsm/x509"
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
	SignSm2Cert        *gmx509.Certificate
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

	sm2cert := gm.ParseX509Certificate2Sm2(&template)
	sm2cert.PublicKey = sm2PubKey
	sm2cert.SignatureAlgorithm = gmx509.SM2WithSM3
	x509Cert, err := genCertificateGMSM2(baseDir, name, sm2cert, sm2cert, sm2PubKey, priv)
	if err != nil {
		return nil, err
	}
	ca = &CA{
		Name: name,
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
) (*gmx509.Certificate, error) {

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

	template.PublicKey = pub
	sm2Tpl := gm.ParseX509Certificate2Sm2(&template)
	sm2Tpl.SignatureAlgorithm =gmx509.SM2WithSM3
	cert, err := genCertificateGMSM2(baseDir, name, sm2Tpl, ca.SignSm2Cert, pub, ca.Sm2Key)

	if err != nil {
		return nil, err
	}

	return cert, nil
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
func genCertificateGMSM2(baseDir, name string, template, parent *gmx509.Certificate, pub *sm2.PublicKey,
	key bccsp.Key) (*gmx509.Certificate, error) {
	//create the x509 public cert
	certBytes, err := gm.CreateCertificateToMem(template, parent, key)

	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	err = ioutil.WriteFile(fileName, certBytes, os.FileMode(0666))
	fmt.Println("fileName:",fileName)

	if err != nil {
		return nil, err
	}

	x509Cert, err := gmx509.ReadCertificateFromMem(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil

}

// LoadCertificateGMSM2 load a ecdsa cert from a file in cert path
func LoadCertificateGMSM2(certPath string) (*gmx509.Certificate, error) {
	var cert *gmx509.Certificate
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
