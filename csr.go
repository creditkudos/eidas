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
)

func GenerateCSR(
	countryCode string, orgName string, orgID string, commonName string, roles []string, qcType asn1.ObjectIdentifier) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	ca, err := CompetentAuthorityForCountryCode(countryCode)
	if err != nil {
		return nil, nil, fmt.Errorf("eidas: %v", err)
	}

	qc, err := Serialize(roles, *ca, qcType)
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

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Version: 0,
		Subject: pkix.Name{
			CommonName:   commonName,
			Country:      []string{countryCode},
			Organization: []string{orgName + "/2.5.4.97=" + orgID},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		ExtraExtensions: []pkix.Extension{
			KeyUsageExtension(keyUsage),
			extendedKeyUsageExtension(extendedKeyUsage),
			subjectKeyIdentifier(key.PublicKey),
			qcStatementsExtension(qc),
		},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate csr: %v", err)
	}
	return csr, key, nil
}

func keyUsageForType(t asn1.ObjectIdentifier) ([]KeyUsage, error) {
	if t[len(t)-1] == QWACType[len(QWACType)-1] {
		return []KeyUsage{
			DigitalSignature,
		}, nil
	} else if t[len(t)-1] == QSEALType[len(QWACType)-1] {
		return []KeyUsage{
			DigitalSignature,
			NonRepudiation,
		}, nil
	}
	return nil, fmt.Errorf("unknown QC type: %v", t)
}

type KeyUsage uint

const (
	DigitalSignature KeyUsage = 0
	NonRepudiation   KeyUsage = 1
	KeyEncipherment  KeyUsage = 2
	DataEncipherment KeyUsage = 3
	KeyAgreement     KeyUsage = 4
	KeyCertSign      KeyUsage = 5
	CRLSign          KeyUsage = 6
	EncipherOnly     KeyUsage = 7
	DecipherOnly     KeyUsage = 8
)

func KeyUsageExtension(usages []KeyUsage) pkix.Extension {
	x := uint16(0)
	for _, usage := range usages {
		x |= (uint16(1) << (7 - uint(usage)))
	}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, x)
	bits := asn1.BitString{
		Bytes:     b,
		BitLength: int(DecipherOnly) + 1,
	}
	d, _ := asn1.Marshal(bits)
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		Value:    d,
	}
}

func extendedKeyUsageForType(t asn1.ObjectIdentifier) ([]asn1.ObjectIdentifier, error) {
	if t[len(t)-1] == QWACType[len(QWACType)-1] {
		return []asn1.ObjectIdentifier{
			TLSWWWServerAuthUsage,
			TLSWWWClientAuthUsage,
		}, nil
	} else if t[len(t)-1] == QSEALType[len(QWACType)-1] {
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

func qcStatementsExtension(data []byte) pkix.Extension {
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3},
		Critical: false,
		Value:    data,
	}
}
