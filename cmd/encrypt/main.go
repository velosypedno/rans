package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"os"

	"golang.org/x/crypto/ssh"
)

const sshPubKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuaKdhK+oaLF2UtyMlVmFCqC4fqPYPTGd+ewTJSYBXU8ZRXFH9TTD4JGl7HFMbLSgG2ER5VvsnfQu1WD0fQT2ndzLl47yJkrQmHwuI3UJjcafr0Ej7vhnVHhTux61DL+DZZ45cmtaxE2bnGERCjq3PtIZGV8fPxV+zD0l1eKD3abHwdA1VxUBX3AbdJWlKD01hUuWIxohC2RYxZFfjlLdQM64XylIuSOFcLNmJZINVI5oSh2fQxP2YxS/PQW+SC9Y+yQA+/zHOlFToxYz3uW3RPxul8BDOJPKeLyNKQO+mLNFgkZrdkJXL+9kvTZdqdC4E7BFKg2721aECy53SuAZz Artur@gora`

func main() {
	m := map[string]string{"document.txt": "aes_key_123"}
	plain, _ := json.Marshal(m)

	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPubKey))
	if err != nil {
		panic(err)
	}
	pubKey := parsedPub.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey)

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		panic(err)
	}

	ciph, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)

	os.WriteFile("lock.dat", append(encKey, ciphertext...), 0644)
}
