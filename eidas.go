package eidas

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

var roleMap = map[string]int{
	"PSP_AS": 1,
	"PSP_PI": 2,
	"PSP_AI": 3,
	"PSP_IC": 4,
}

type root struct {
	QcType      qcType
	QcStatement qcStatement
}

type qcType struct {
	OID    asn1.ObjectIdentifier
	Detail []asn1.ObjectIdentifier
}

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

// Serialize will serialize the given roles and CA information into a DER encoded ASN.1 qualified statement.
func Serialize(roles []string, caName string, caID string) ([]byte, error) {
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
			OID: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6},
			Detail: []asn1.ObjectIdentifier{
				asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3},
			},
		},
		qcStatement{
			OID: asn1.ObjectIdentifier{0, 4, 0, 19495, 2},
			RolesInfo: rolesInfo{
				Roles: rawRoles{
					Roles: r,
				},
				CAName: caName,
				CAID:   caID,
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
	var root root
	_, err := asn1.Unmarshal(d, &root)
	if err != nil {
		return fmt.Errorf("Failed to decode asn.1: %v", err)
	}

	roles := make([]string, 0)
	for _, v := range root.QcStatement.RolesInfo.Roles.Roles {
		if v.Tag == asn1.TagUTF8String {
			var dec string
			_, err := asn1.Unmarshal(v.FullBytes, &dec)
			if err != nil {
				return fmt.Errorf("failed to decode role string: %v", err)
			}
			roles = append(roles, dec)
		}
	}

	fmt.Printf("CA { Name: %s ID: %s } Roles: %v\n", root.QcStatement.RolesInfo.CAName, root.QcStatement.RolesInfo.CAID, roles)
	return nil
}

// Dump outputs to stdout a human-readable representation of a hex encoded qualified statement.
func DumpFromHex(h string) error {
	d, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("Failed to decode hex: %v", err)
	}

	return Dump(d)
}

// Extract returns the roles, CA name and CA ID from an encoded qualified statement.
func Extract(data []byte) ([]string, string, string, error) {
	var root root
	_, err := asn1.Unmarshal(data, &root)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to decode eIDAS: %v", err)
	}

	roles := make([]string, 0)
	for _, v := range root.QcStatement.RolesInfo.Roles.Roles {
		if v.Tag == asn1.TagUTF8String {
			var dec string
			_, err := asn1.Unmarshal(v.FullBytes, &dec)
			if err != nil {
				return nil, "", "", fmt.Errorf("failed to decode eIDAS role: %v", err)
			}
			roles = append(roles, dec)
		}
	}

	return roles, root.QcStatement.RolesInfo.CAName, root.QcStatement.RolesInfo.CAID, nil
}
