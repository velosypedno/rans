package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

const privPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEArminYSvqGixdlLcjJVZhQqguH6j2D0xnfnsEyUmAV1PGUVxR
/U0w+CRpexxTGy0oBthEeVb7J30LtVg9H0E9p3cy5eO8iZK0Jh8LiN1CY3Gn69BI
+74Z1R4U7setQy/g2WeOXJrWsRNm5xhEQo6tz7SGRlfHz8Vfsw9JdXig92mx8HQN
VcVAV9wG3SVpSg9NYVLliMaIQtkWMWRX45S3UDOuF8pSLkjhXCzZiWSDVSOaEodn
0MT9mMUvz0FvkgvWPskAPv8xzpRU6MWM97lt0T8bpfAQziTyni8jSkDvpizRYJGa
3ZCVy/vZL02XanQuBOwRSoNu9tWhAsud0rgGcwIDAQABAoIBAAU38oS42+OWJLUM
UCStFn4D9lT7AE3PszdtB+UKgXpELKxYRlOUuwVT7Nw87/SQK3hMO9oX+MU6ZGRu
HPoUqW94qnPkxPjVBDu9DCgrz8LzKLKdCeQxuWI+OmjvL2dpHGG6wBlUEgFIHnko
tTkSPcFsN1iB7xI1rXE97ImiD+F7nFnC4rT/gmBBeZb1K98oWjJvi9v2qGEPXuHN
3tIG97PdVVyX/12ZBtnqhvgiQ+uts1UBuve9DtMfRfzV9LxtugNCoOU+M7Ot6OMa
WaHQfOOuAPEoMvu91K5zJlE6ljIoDsdNt+iDP9xcGGj/gK+CMcKKgTgIYwPm78BX
bcsokuECgYEA2n+BpmFhHACDWstyhbNFDPVq0V23Si2TWHPF9hhkYx+TeJlzFsm6
S5az+34RDYzTfMaOH2lsdru2p8MsRp5OOP8l4JX3sFPw/D3OQex1VBhxoMcCF2qr
ViRxqL23CNVPB/OrWfMCzQCt550Upu7iy9AaC+K8oxALU9jYJFqrHhMCgYEAzFft
h03rWPQMR6Hx2P1LfvnexXU7koygZyV0ejg8iOr8OmSFuXj6aDekFQIISV+jffuH
ozpkZgNQAUt7tuEnfCmCMXYaRTwGgdeo6NaLV3GPj23WlOpWmUCZhOtyvreyWi4w
Yi0MPLyeFsoB++2O+Zabu3ryjb8S+qyZz7t/AiECgYEApcxPUzNdfuQcyI7Mrguk
f/rSPWDBrrX6swnW07Eaq+TQAJlgLZCRnr4SgOnegsuzx2Dbg5Z5yXcTWSXOuR9y
9+kUkuD5fIGVwbIciwWk2lVaE8gvHBnDPbCV1pdvBnLmb4BFLBIss+aqD7CwdSOc
UU/uE8rPnWSVU+Cd0qhCZKUCgYEAxtyvMWUYK5pdtPyaY4Sliy3aqalcT1OB6r+d
qi++YbTlwGIBba2ZbADyMuumatmjP0ChEK4L9Oc2Xfw6qpBVn9S5ei8og8ZVwtjA
7c+VDYVbo8bN9GBV5JDklmGYaphU/sRCm9ihNx6MbzsqUSUwZh828W5GTMHt03xT
t8ENamECgYEAoh1JEhd+UAfoc56jvz7KNlvvGP2DksJu9EDQK0Sw7zQpb1ECgcVJ
EPDkGaOC1ynT/gBPfQ0wP5iiSXIOz+zhIeWxqRJG54QsghTzbuEQDF5aVeSzh4al
Zg9JnK5k+QQmuihLjCQkvpn4QGDZIROe7HxzzUDA7Tk6Jbspr+1sIGI=
-----END RSA PRIVATE KEY-----`

func main() {
	data, err := os.ReadFile("lock.dat")
	if err != nil {
		panic(err)
	}

	encKey, ciphertext := data[:256], data[256:]

	block, _ := pem.Decode([]byte(privPEM))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		panic(fmt.Errorf("RSA decryption failed: %v", err))
	}

	ciph, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		panic(err)
	}

	nonceSize := gcm.NonceSize()
	plain, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		panic(err)
	}

	var m map[string]string
	json.Unmarshal(plain, &m)
	fmt.Println(m)
}
