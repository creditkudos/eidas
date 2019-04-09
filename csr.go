package eidas

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/creditkudos/eidas/qcstatements"
)

func GenerateCSR(
	countryCode string, orgName string, orgID string, commonName string, roles []string, qcType asn1.ObjectIdentifier) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	ca, err := qcstatements.CompetentAuthorityForCountryCode(countryCode)
	if err != nil {
		return nil, nil, fmt.Errorf("eidas: %v", err)
	}

	qc, err := qcstatements.Serialize(roles, *ca, qcType)
	if err != nil {
		return nil, nil, fmt.Errorf("eidas: %v", err)
	}

	keyUsage, err := keyUsageForType(qcType)
	if err != nil {
		return nil, nil, err
	}
	extendedKeyUsage, err := extendedKeyUsageForType(qcType)
	if err != nil {
		return nil, nil, err
	}

	extensions := []pkix.Extension{
		KeyUsageExtension(keyUsage),
	}
	if len(extendedKeyUsage) != 0 {
		extensions = append(extensions, extendedKeyUsageExtension(extendedKeyUsage))
	}
	extensions = append(extensions, subjectKeyIdentifier(key.PublicKey), qcStatementsExtension(qc))

	subject, err := buildSubject(countryCode, orgName, commonName, orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build CSR subject: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Version:            0,
		RawSubject:         subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		ExtraExtensions:    extensions,
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate csr: %v", err)
	}
	return csr, key, nil
}

func keyUsageForType(t asn1.ObjectIdentifier) ([]x509.KeyUsage, error) {
	if t.Equal(qcstatements.QWACType) {
		return []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
		}, nil
	} else if t.Equal(qcstatements.QSEALType) {
		return []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageContentCommitment, // Also known as NonRepudiation.
		}, nil
	}
	return nil, fmt.Errorf("unknown QC type: %v", t)
}

func KeyUsageExtension(usages []x509.KeyUsage) pkix.Extension {
	x := uint16(0)
	for _, usage := range usages {
		x |= (uint16(1) << (8 - uint(usage)))
	}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, x)
	bits := asn1.BitString{
		Bytes:     b,
		BitLength: int(x509.KeyUsageDecipherOnly),
	}
	d, _ := asn1.Marshal(bits)
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		Value:    d,
	}
}

func extendedKeyUsageForType(t asn1.ObjectIdentifier) ([]asn1.ObjectIdentifier, error) {
	if t.Equal(qcstatements.QWACType) {
		return []asn1.ObjectIdentifier{
			TLSWWWServerAuthUsage,
			TLSWWWClientAuthUsage,
		}, nil
	} else if t.Equal(qcstatements.QSEALType) {
		return []asn1.ObjectIdentifier{}, nil
	}
	return nil, fmt.Errorf("unknown QC type: %v", t)
}

var (
	TLSWWWServerAuthUsage = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	TLSWWWClientAuthUsage = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	CodeSigningUsage      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	EmailProtectionUsage  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	TimeStampingUsage     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	OCSPSigning           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

func extendedKeyUsageExtension(usages []asn1.ObjectIdentifier) pkix.Extension {
	d, _ := asn1.Marshal(usages)

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: false,
		Value:    d,
	}
}

func subjectKeyIdentifier(key rsa.PublicKey) pkix.Extension {
	b := sha1.Sum(x509.MarshalPKCS1PublicKey(&key))
	d, err := asn1.Marshal(b[:])
	if err != nil {
		log.Fatalf("failed to marshal subject key identifier: %v", err)
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 14},
		Critical: false,
		Value:    d,
	}
}

var QCStatementsExt = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

func qcStatementsExtension(data []byte) pkix.Extension {
	return pkix.Extension{
		Id:       QCStatementsExt,
		Critical: false,
		Value:    data,
	}
}

var oidCountryCode = asn1.ObjectIdentifier{2, 5, 4, 6}
var oidOrganizationName = asn1.ObjectIdentifier{2, 5, 4, 10}
var oidOrganizationID = asn1.ObjectIdentifier{2, 5, 4, 97}
var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// Explicitly build subject from attributes to keep ordering.
func buildSubject(countryCode string, orgName string, commonName string, orgID string) ([]byte, error) {
	s := pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{
			pkix.AttributeTypeAndValue{
				Type:  oidCountryCode,
				Value: countryCode,
			},
			pkix.AttributeTypeAndValue{
				Type:  oidOrganizationName,
				Value: orgName,
			},
			pkix.AttributeTypeAndValue{
				Type:  oidOrganizationID,
				Value: orgID,
			},
			pkix.AttributeTypeAndValue{
				Type:  oidCommonName,
				Value: commonName,
			},
		},
	}
	return asn1.Marshal(s.ToRDNSequence())
}
