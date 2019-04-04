package eidas

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestKeyUsage(t *testing.T) {
	Convey("key usage for QWAC", t, func() {
		usage, err := keyUsageForType(QWACType)
		So(err, ShouldBeNil)
		So(usage, ShouldResemble, []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
		})
	})
	Convey("key usage for QSEAL", t, func() {
		usage, err := keyUsageForType(QSEALType)
		So(err, ShouldBeNil)
		So(usage, ShouldResemble, []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageContentCommitment,
		})
	})
}

func TestExtendedKeyUsage(t *testing.T) {
	Convey("extended key usage for QWAC", t, func() {
		usage, err := extendedKeyUsageForType(QWACType)
		So(err, ShouldBeNil)
		So(usage, ShouldResemble, []asn1.ObjectIdentifier{
			TLSWWWServerAuthUsage,
			TLSWWWClientAuthUsage,
		})
	})
}

func TestBuildCSR(t *testing.T) {
	Convey("CSR for QWAC", t, func() {
		data, key, err := GenerateCSR("GB", "Foo Org", "Foo Org ID", "Foo Name", []string{"PSP_AI"}, QWACType)
		So(err, ShouldBeNil)
		So(key, ShouldNotBeNil)
		csr, err := x509.ParseCertificateRequest(data)
		So(err, ShouldBeNil)
		So(csr.Subject.Country, ShouldResemble, []string{"GB"})
		So(csr.Subject.Organization, ShouldResemble, []string{"Foo Org"})
		So(csr.Subject.CommonName, ShouldEqual, "Foo Name")

		names := csr.Subject.Names
		So(names, shouldContainType, asn1.ObjectIdentifier{2, 5, 4, 97})
		for _, name := range names {
			if name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 97}) {
				So(name.Value, ShouldEqual, "Foo Org ID")
			}
		}

		exts := csr.Extensions
		So(exts, shouldContainId, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3})
		for _, ext := range exts {
			if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}) {
				roles, caName, caID, err := Extract(ext.Value)
				So(err, ShouldBeNil)
				So(roles, ShouldResemble, []string{"PSP_AI"})
				So(caName, ShouldEqual, "Financial Conduct Authority")
				So(caID, ShouldEqual, "GB-FCA")
			}
		}
	})
}

func shouldContainType(actual interface{}, expected ...interface{}) string {
	attrs, ok := actual.([]pkix.AttributeTypeAndValue)
	if !ok {
		return "Expected []pkix.AttributeTypeAndValue"
	}
	for _, v := range attrs {
		ex, ok := expected[0].(asn1.ObjectIdentifier)
		if !ok {
			return "Expected asn1.ObjectIdentifier"
		}
		if v.Type.Equal(ex) {
			return ""
		}
	}
	return fmt.Sprintf("Expected to find: %v", expected)
}

func shouldContainId(actual interface{}, expected ...interface{}) string {
	exts, ok := actual.([]pkix.Extension)
	if !ok {
		return "Expected []x509.Extension"
	}
	ex, ok := expected[0].(asn1.ObjectIdentifier)
	if !ok {
		return "Expected asn1.ObjectIdentifier"
	}
	for _, ext := range exts {
		if ext.Id.Equal(ex) {
			return ""
		}
	}
	return fmt.Sprintf("Expected to find: %v", expected)
}
