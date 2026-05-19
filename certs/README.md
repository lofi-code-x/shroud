# Development TLS Certificates

The default local configs expect a local CA plus a server certificate signed by that CA:

- `certs/ca.crt`
- `certs/localhost.crt`
- `certs/localhost.key`

Generate them with:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/ca.key \
  -out certs/ca.crt \
  -days 365 \
  -subj "/CN=shroud-dev-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey rsa:2048 -nodes \
  -keyout certs/localhost.key \
  -out certs/localhost.csr \
  -subj "/CN=localhost"

openssl x509 -req \
  -in certs/localhost.csr \
  -CA certs/ca.crt \
  -CAkey certs/ca.key \
  -CAcreateserial \
  -out certs/localhost.crt \
  -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
```

Do not use these development keys in production.
