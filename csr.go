package eidas

import (
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
