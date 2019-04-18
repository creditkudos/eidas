package eidas

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/creditkudos/eidas/qcstatements"
	. "github.com/smartystreets/goconvey/convey"
)

func TestKeyUsage(t *testing.T) {
	Convey("key usage for QWAC", t, func() {
		usage, err := keyUsageForType(qcstatements.QWACType)
		So(err, ShouldBeNil)
		So(usage, ShouldResemble, []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
		})
	})
	Convey("key usage for QSEAL", t, func() {
		usage, err := keyUsageForType(qcstatements.QSEALType)
		So(err, ShouldBeNil)
		So(usage, ShouldResemble, []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageContentCommitment,
		})
	})
}

func TestExtendedKeyUsage(t *testing.T) {
	Convey("extended key usage for QWAC", t, func() {
		usage, err := extendedKeyUsageForType(qcstatements.QWACType)
		So(err, ShouldBeNil)
		So(usage, ShouldResemble, []asn1.ObjectIdentifier{
			TLSWWWServerAuthUsage,
			TLSWWWClientAuthUsage,
		})
	})
}

func TestBuildCSR(t *testing.T) {
	Convey("CSR for QWAC", t, func() {
		data, key, err := GenerateCSR("GB", "Foo Org", "Foo Org ID", "Foo Name", []qcstatements.Role{qcstatements.RoleAccountInformation}, qcstatements.QWACType)
		So(err, ShouldBeNil)
		So(key, ShouldNotBeNil)
		csr, err := x509.ParseCertificateRequest(data)
		So(err, ShouldBeNil)
		So(csr.Subject.Country, ShouldResemble, []string{"GB"})
		So(csr.Subject.Organization, ShouldResemble, []string{"Foo Org"})
		So(csr.Subject.CommonName, ShouldEqual, "Foo Name")

		names := csr.Subject.Names
		So(names, ShouldHaveLength, 4)

		So(names[0].Type, ShouldEqual, oidCountryCode)
		So(names[0].Value, ShouldEqual, "GB")

		So(names[1].Type, ShouldEqual, oidOrganizationName)
		So(names[1].Value, ShouldEqual, "Foo Org")

		So(names[2].Type, ShouldEqual, oidOrganizationID)
		So(names[2].Value, ShouldEqual, "Foo Org ID")

		So(names[3].Type, ShouldEqual, oidCommonName)
		So(names[3].Value, ShouldEqual, "Foo Name")

		exts := csr.Extensions
		So(exts, shouldContainId, QCStatementsExt)
		// Should have key usage
		So(exts, shouldContainId, asn1.ObjectIdentifier{2, 5, 29, 15})
		// Should have extended key usage.
		So(exts, shouldContainId, asn1.ObjectIdentifier{2, 5, 29, 37})
		for _, ext := range exts {
			if ext.Id.Equal(QCStatementsExt) {
				roles, caName, caID, err := qcstatements.Extract(ext.Value)
				So(err, ShouldBeNil)
				So(roles, ShouldResemble, []qcstatements.Role{qcstatements.RoleAccountInformation})
				So(caName, ShouldEqual, "Financial Conduct Authority")
				So(caID, ShouldEqual, "GB-FCA")
			}
		}
	})
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
