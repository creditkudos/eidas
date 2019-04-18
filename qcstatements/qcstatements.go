// Package qcstatements contains functions for building and extracting qualified
// statements for PSD2 qualified certificates.
// See ETSI TS 119 495 v1.2.1 and RFC 3739.
package qcstatements

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

type Role string

const (
	// Account servicing role.
	RoleAccountServicing Role = "PSP_AS"
	// Payment initiation role.
	RolePaymentInitiation Role = "PSP_PI"
	// Account information role.
	RoleAccountInformation Role = "PSP_AI"
	// Issuing of card-based payment instruments role.
	RolePaymentInstruments Role = "PSP_IC"
)

// CompetentAuthority under PSD2.
type CompetentAuthority struct {
	// Name of the authority, e.g. "Financial Conduct Authority".
	Name string
	// NCA identifier of the authority, e.g. "GB-FCA".
	ID string
}

// CompetentAuthorityForCountryCode returns the correct competent authority
// string, e.g., "GB-FCA", based on the given country code.
func CompetentAuthorityForCountryCode(code string) (*CompetentAuthority, error) {
	if ca, ok := caMap[code]; ok {
		return ca, nil
	}
	return nil, fmt.Errorf("unknown country code: %s", code)
}

// Maps ISO-3166-1 alpha-2 codes to a CompetentAuthority.
// See ETSI TS 119 495 V1.2.1 (2018-11) Annex D.
var caMap = map[string]*CompetentAuthority{
	"AT": &CompetentAuthority{
		ID:   "AT-FMA",
		Name: "Austria Financial Market Authority",
	},
	"BE": &CompetentAuthority{
		ID:   "BE-NBB",
		Name: "National Bank of Belgium",
	},
	"BG": &CompetentAuthority{
		ID:   "BG-BNB",
		Name: "Bulgarian National Bank",
	},
	"HR": &CompetentAuthority{
		ID:   "HR-CNB",
		Name: "Croatian National Bank",
	},
	"CY": &CompetentAuthority{
		ID:   "CY-CBC",
		Name: "Central Bank of Cyprus",
	},
	"CZ": &CompetentAuthority{
		ID:   "CZ-CNB",
		Name: "Czech National Bank",
	},
	"DK": &CompetentAuthority{
		ID:   "DK-DFSA",
		Name: "Danish Financial Supervisory Authority",
	},
	"EE": &CompetentAuthority{
		ID:   "EE-FI",
		Name: "Estonia Financial Supervisory Authority",
	},
	"FI": &CompetentAuthority{
		ID:   "FI-FINFSA",
		Name: "Finnish Financial Supervisory Authority",
	},
	"FR": &CompetentAuthority{
		ID:   "FR-ACPR",
		Name: "Prudential Supervisory and Resolution Authority",
	},
	"DE": &CompetentAuthority{
		ID:   "DE-BAFIN",
		Name: "Federal Financial Supervisory Authority",
	},
	"GR": &CompetentAuthority{
		ID:   "GR-BOG",
		Name: "Bank of Greece",
	},
	"HU": &CompetentAuthority{
		ID:   "HU-CBH",
		Name: "Central Bank of Hungary",
	},
	"IS": &CompetentAuthority{
		ID:   "IS-FME",
		Name: "Financial Supervisory Authority",
	},
	"IE": &CompetentAuthority{
		ID:   "IE-CBI",
		Name: "Central Bank of Ireland",
	},
	"IT": &CompetentAuthority{
		ID:   "IT-BI",
		Name: "Bank of Italy",
	},
	"LI": &CompetentAuthority{
		ID:   "LI-FMA",
		Name: "Financial Market Authority Liechtenstein",
	},
	"LV": &CompetentAuthority{
		ID:   "LV-FCMC",
		Name: "Financial and Capital Markets Commission",
	},
	"LT": &CompetentAuthority{
		ID:   "LT-BL",
		Name: "Bank of Lithuania",
	},
	"LU": &CompetentAuthority{
		ID:   "LU-CSSF",
		Name: "Commission for the Supervision of Financial Sector",
	},
	"NO": &CompetentAuthority{
		ID:   "NO-FSA",
		Name: "The Financial Supervisory Authority of Norway",
	},
	"MT": &CompetentAuthority{
		ID:   "MT-MFSA",
		Name: "Malta Financial Services Authority",
	},
	"NL": &CompetentAuthority{
		ID:   "NL-DNB",
		Name: "The Netherlands Bank",
	},
	"PL": &CompetentAuthority{
		ID:   "PL-PFSA",
		Name: "Polish Financial Supervision Authority",
	},
	"PT": &CompetentAuthority{
		ID:   "PT-BP",
		Name: "Bank of Portugal",
	},
	"RO": &CompetentAuthority{
		ID:   "RO-NBR",
		Name: "National bank of Romania",
	},
	"SK": &CompetentAuthority{
		ID:   "SK-NBS",
		Name: "National Bank of Slovakia",
	},
	"SI": &CompetentAuthority{
		ID:   "SI-BS",
		Name: "Bank of Slovenia",
	},
	"ES": &CompetentAuthority{
		ID:   "ES-BE",
		Name: "Bank of Spain",
	},
	"SE": &CompetentAuthority{
		ID:   "SE-FINA",
		Name: "Swedish Financial Supervision Authority",
	},
	"GB": &CompetentAuthority{
		ID:   "GB-FCA",
		Name: "Financial Conduct Authority",
	},
}

var roleMap = map[Role]int{
	RoleAccountServicing:   1,
	RolePaymentInitiation:  2,
	RoleAccountInformation: 3,
	RolePaymentInstruments: 4,
}

type root struct {
	QcType      qcType
	QcStatement qcStatement
}

type qcType struct {
	OID    asn1.ObjectIdentifier
	Detail []asn1.ObjectIdentifier
}

var (
	QSEALType = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}
	QWACType  = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}
)

type qcStatement struct {
	OID       asn1.ObjectIdentifier
	RolesInfo rolesInfo
}

type rolesInfo struct {
	Roles  rawRoles
	CAName string `asn1:"utf8"`
	CAID   string `asn1:"utf8"`
}

type rawRoles struct {
	// eIDAS roles consist a sequence of an object identifier and a UTF8 string for each role
	// Unfortunately, the asn1 package cannot cope with non-uniform arrays so RawValues must
	// be used here and then decoded further elsewhere.
	Roles []asn1.RawValue
}

// Serialize will serialize the given roles and CA information into a DER encoded ASN.1 qualified statement. qcType should be one of QWACType or QSEALType.
func Serialize(roles []Role, ca CompetentAuthority, t asn1.ObjectIdentifier) ([]byte, error) {
	r := make([]asn1.RawValue, len(roles)*2)
	for i, rv := range roles {
		if _, ok := roleMap[rv]; !ok {
			return nil, fmt.Errorf("Unknown role: %s", rv)
		}
		d, err := asn1.Marshal(asn1.ObjectIdentifier(
			[]int{0, 4, 0, 19495, 1, roleMap[rv]}))
		if err != nil {
			return nil, fmt.Errorf("Failed to encode OID for role %s: %v", rv, err)
		}
		r[i*2] = asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagOID,
			IsCompound: false,
			FullBytes:  d,
		}
		ds, err := asn1.Marshal(rv)
		if err != nil {
			return nil, fmt.Errorf("Failed to encode string for role %s: %v", rv, err)
		}
		r[i*2+1] = asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagUTF8String,
			IsCompound: false,
			FullBytes:  ds,
		}
	}

	fin, err := asn1.Marshal(root{
		qcType{
			OID:    asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6},
			Detail: []asn1.ObjectIdentifier{t},
		},
		qcStatement{
			OID: asn1.ObjectIdentifier{0, 4, 0, 19495, 2},
			RolesInfo: rolesInfo{
				Roles: rawRoles{
					Roles: r,
				},
				CAName: ca.Name,
				CAID:   ca.ID,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal eIDAS: %v", err)
	}
	return fin, nil
}

// Dump outputs to stdout a human-readable representation of an encoded qualified statement.
func Dump(d []byte) error {
	roles, name, id, err := Extract(d)
	if err != nil {
		return fmt.Errorf("eidas: %v", err)
	}

	fmt.Printf("CA { Name: %s ID: %s } Roles: %v\n", name, id, roles)
	return nil
}

// DumpFromHex outputs to stdout a human-readable representation of a hex encoded qualified statement.
func DumpFromHex(h string) error {
	d, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("Failed to decode hex: %v", err)
	}

	return Dump(d)
}

// Extract returns the roles, CA name and CA ID from an encoded qualified statement.
func Extract(data []byte) ([]Role, string, string, error) {
	var root root
	_, err := asn1.Unmarshal(data, &root)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to decode eIDAS: %v", err)
	}

	roles := make([]Role, 0)
	for _, v := range root.QcStatement.RolesInfo.Roles.Roles {
		if v.Tag == asn1.TagUTF8String {
			var dec Role
			_, err := asn1.Unmarshal(v.FullBytes, &dec)
			if err != nil {
				return nil, "", "", fmt.Errorf("failed to decode eIDAS role: %v", err)
			}
			roles = append(roles, dec)
		}
	}

	return roles, root.QcStatement.RolesInfo.CAName, root.QcStatement.RolesInfo.CAID, nil
}
