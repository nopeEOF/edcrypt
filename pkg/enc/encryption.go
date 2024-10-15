package encryption

import (
	options "EDCrypt/pkg/flag"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type Encryption struct {
	Key string
	Opt options.Option
}

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 1000, 32, sha256.New)
}

func readFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return data, err
	}
	return data, nil
}

func writeFile(filePath string, data []byte) error {
	return os.WriteFile(filePath, data, 0400)
}

func (e *Encryption) EncryptFile() error {
    plainText, err := readFile(e.Opt.File)
    if err != nil {
        return err
    }

    // Generate a random salt
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return err
    }

    // Derive a key from the password
    key := deriveKey(e.Key, salt)

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return err
    }

    cipherText := gcm.Seal(nonce, nonce, plainText, nil)

    // Append salt to the encrypted message
    finalCipherText := append(salt, cipherText...)
	encryptText := base64.StdEncoding.EncodeToString(finalCipherText)
	writeFile(e.Opt.Output, []byte(encryptText))
    return nil
}

func (e *Encryption) DecryptFile() (string, error) {
	plainText, err := readFile(e.Opt.File)
    if err != nil {
        return "", err
    }
	decodedCipherText, err := base64.StdEncoding.DecodeString(string(plainText))

    if err != nil {
        return "", err
    }

    // Extract the salt from the beginning of the decoded data
    salt := decodedCipherText[:16]
    cipherText := decodedCipherText[16:]

    // Derive the key using the salt
    key := deriveKey(e.Key, salt)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

    plainText, err = gcm.Open(nil, nonce, cipherText, nil)
    if err != nil {
        return "", err
    }

	return string(plainText), nil
}

func (e *Encryption) GetApp(input string) (string, error) {
    // Create a new reader from the string
    reader := strings.NewReader(input)

    // Use bufio.Scanner to read line by line
    scanner := bufio.NewScanner(reader)

    for scanner.Scan() {
        line := scanner.Text()
        if strings.Contains(line, e.Opt.App) {
            return line, nil
        }
    }

    // Check for errors during the scan
    if err := scanner.Err(); err != nil {
        return  "", err
    }

    return "", nil
}

func (e *Encryption) SaveInClipboard(input string) error {
    // Create a command to run xsel
    cmd := exec.Command("xsel", "--clipboard", "--input")
    cmd.Stdin = strings.NewReader(input)

    // Run the command
    err := cmd.Run()
    if err != nil {
        return err
    }

    return nil
}

