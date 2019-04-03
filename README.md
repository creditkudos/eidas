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
