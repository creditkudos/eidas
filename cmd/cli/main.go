package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/creditkudos/eidas"
)

var countryCode = flag.String("country-code", "GB", "ISO-3166-1 Alpha 2 country code")
var orgName = flag.String("organization-name", "Credit Kudos", "Organization name")
var orgID = flag.String("organization-id", "123456", "Organization ID")
var commonName = flag.String("common-name", "abcdef", "Common Name")
var roles = flag.String("roles", eidas.RoleAccountInformation, "eIDAS roles; comma-separated list from [PSP_AS, PSP_PI, PSP_AI, PSP_IC]")

func main() {
	flag.Parse()

	out, err := eidas.GenerateCSRConfigFile(
		*countryCode, *orgName, *orgID, *commonName,
		strings.Split(*roles, ","))
	if err != nil {
		log.Fatalf("Failed to generate CSR: %v", err)
	}
	fmt.Println(out)
}
