package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
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
	targetDir := parseTargetDirectory()
	fmt.Printf("[*] Target directory for decryption: %s\n", targetDir)

	// 1. Read and parse lock.dat to get the file-to-key mapping
	fileKeys, err := loadAndDecryptMetadata(targetDir)
	if err != nil {
		panic(err)
	}

	// 2. Restore each file using its specific AES key
	if err := decryptFilesInDirectory(fileKeys); err != nil {
		panic(err)
	}

	// 3. Remove lock.dat after successful recovery
	os.Remove(filepath.Join(targetDir, "lock.dat"))

	fmt.Println("[+] Decryption complete. All files successfully restored.")
}

func parseTargetDirectory() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return "."
}

func loadAndDecryptMetadata(targetDir string) (map[string]string, error) {
	lockPath := filepath.Join(targetDir, "lock.dat")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("lock.dat not found: %w", err)
	}

	if len(data) < 256 {
		return nil, fmt.Errorf("malformed lock.dat file")
	}

	encSessionKey, ciphertext := data[:256], data[256:]

	privKey := parsePrivateKey(privPEM)
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encSessionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed: %w", err)
	}

	plainData := decryptBytes(ciphertext, sessionKey)

	var fileKeys map[string]string
	if err := json.Unmarshal(plainData, &fileKeys); err != nil {
		return nil, fmt.Errorf("failed to parse metadata json: %w", err)
	}

	return fileKeys, nil
}

func decryptFilesInDirectory(fileKeys map[string]string) error {
	for filePath, keyHex := range fileKeys {
		aesKey, err := hex.DecodeString(keyHex)
		if err != nil {
			return fmt.Errorf("invalid key format for %s: %w", filePath, err)
		}

		if err := decryptSingleFile(filePath, aesKey); err != nil {
			return fmt.Errorf("failed to decrypt file %s: %w", filePath, err)
		}
		fmt.Printf("[Decrypted] %s\n", filePath)
	}
	return nil
}

func decryptSingleFile(filePath string, aesKey []byte) error {
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	plaintext := decryptBytes(ciphertext, aesKey)
	return os.WriteFile(filePath, plaintext, 0644)
}

func decryptBytes(ciphertext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		panic("ciphertext too short")
	}

	nonce, encryptedPayload := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

func parsePrivateKey(pemStr string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		panic("failed to parse private key PEM")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return priv
}
