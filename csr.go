package eidas

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
)

func GenerateCSRConfigFile(
	countryCode string, orgName string, orgID string, commonName string, roles []string) (string, error) {
	ca, err := CompetentAuthorityForCountryCode(countryCode)
	if err != nil {
		return "", fmt.Errorf("eidas: %v", err)
	}
	qc, err := Serialize(roles, *ca)
	if err != nil {
		return "", fmt.Errorf("eidas: %v", err)
	}

	tmpl, err := template.ParseFiles("data/obwac_template.cnf")
	if err != nil {
		return "", fmt.Errorf("eidas: failed to load obwac template: %v", err)
	}

	out := &strings.Builder{}
	err = tmpl.Execute(out, struct {
		CountryCode            string
		OrganizationName       string
		OrganizationIdentifier string
		CommonName             string
		QCStatement            string
		Roles                  string
	}{
		CountryCode:            countryCode,
		OrganizationName:       orgName,
		OrganizationIdentifier: orgID,
		CommonName:             commonName,
		QCStatement:            hex.EncodeToString(qc),
		Roles:                  strings.Join(roles, ","),
	})
	if err != nil {
		return "", fmt.Errorf("eidas: failed to execute template: %v", err)
	}
	return out.String(), nil
}

func GenerateCSR(
	countryCode string, orgName string, orgID string, commonName string, roles []string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Version: 0,
		Subject: pkix.Name{
			CommonName:   commonName,
			Country:      []string{countryCode},
			Organization: []string{orgName+"/2.5.4.97="+orgID},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		ExtraExtensions: []pkix.Extension{
			keyUsageExtension(),
			extendedKeyUsageExtension(),
		},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate csr: %v", err)
	}
	return csr, nil
}

const (
	digitalSignature = 0
	nonRepudiation = 1
	keyEncipherment = 2
	dataEncipherment = 3
	keyAgreement = 4
	keyCertSign = 5
	cRLSign = 6
	encipherOnly = 7
	decipherOnly = 8
)

func keyUsageExtension() pkix.Extension {
	x := uint16(0)
	x |= (uint16(1) << digitalSignature)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, x)
	bits := asn1.BitString{
		Bytes: b,
		BitLength: decipherOnly + 1,
	}
	d, _ := asn1.Marshal(bits)
	return pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		Value: d,
	}
}

func extendedKeyUsageExtension() pkix.Extension {
	x := []asn1.ObjectIdentifier{
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1},
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2},
	}
	d, _ := asn1.Marshal(x)

	return pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: false,
		Value: d,
	}
}
