# eIDAS
Tools for reading and creating eIDAS certificate signing requests

## Generating a Ceritificate Signing Request (CSR)
```bash
go run cmd/cli/main.go
```

You can see the available flags with
```
go run cmd/cli/main.go -help
```

By default this will generate two files: `out.csr` and `out.key` containing the CSR and the private key, respectively.

To print out the details of the CSR for debugging, run:
```
openssl req -in out.csr -text
```

## Notes on CSR format

For both QWAC and QSEAL types the following attributes are required in the CSR:

### [Subject](https://tools.ietf.org/html/rfc5280#section-4.1.2.6)
* Must contain country code, organisation name and common name.
* Must also contain the organisation ID. Organisation ID (ITU-T X.520 10/2012 Section 6.4.4) isn't supported by most tools by default (including OpenSSL and go) but this can be added to the subject as a custom name with the ASN.1 OID of `2.5.4.97`.

### Key Parameters
* Key should be 2048-bit RSA.
* Signature algorithm should be `SHA256WithRSA`.

### Extensions

#### [Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.3)
* X509v3 Key Usage extension should be marked as `critical`.
* For QWAC, it should include "Digital Signature".
* For QSEAL, it should include "Digital Signature" and "Non Repudiation" (also know as "Content Commitment").

#### [Extended Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.12)
* For QWAC, it should include "TLS Web Server Authentication" and "TLS Web Client Authentication".
* For QSEAL, it should be empty.

#### [Subject Key Identifier](https://tools.ietf.org/html/rfc5280#section-4.2.1.2)
* Should be the 160-bit SHA1 sum of the PKCS1 public key.

#### [qcStatements](https://tools.ietf.org/html/rfc3739.html#section-3.2.6)
This is an extension used by eIDAS as documented here [ETSI TS 119 495 Annex A](https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.02.01_60/ts_119495v010201p.pdf).
The required parameters included in this are the Competent Authority's name and ID, e.g. "Financial Conduct Authority" and "GB-FCA", and the roles the TPP requires, e.g. "PSP_AI" (Account Information).
