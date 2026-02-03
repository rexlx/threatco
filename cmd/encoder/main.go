package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/rexlx/threatco/internal"
)

func main() {
	inputFile := flag.String("input", "config.json", "Plaintext JSON config file")
	outputFile := flag.String("output", "config.enc", "Output encrypted file")
	seedFile := flag.String("seed", "", "Path to the seed file")
	flag.Parse()

	partialKey := os.Getenv("THREATCO_CONFIG_KEY")
	if partialKey == "" || *seedFile == "" {
		log.Fatal("Usage: THREATCO_CONFIG_KEY=xxx go run main.go -seed <file> -input <file> -output <file>")
	}

	// 1. Derive Passcode
	f, _ := os.Open(*seedFile)
	seedHash, _ := internal.CalculateSHA256(f)
	passcode := partialKey + seedHash

	// 2. Prepare Encryption
	plaintext, _ := os.ReadFile(*inputFile)
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, salt)
	io.ReadFull(rand.Reader, nonce)

	key := internal.DeriveKey(passcode, salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	// 3. Encrypt and Write Binary: [Salt][Nonce][Ciphertext]
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out, _ := os.Create(*outputFile)
	out.Write(salt)
	out.Write(nonce)
	out.Write(ciphertext)

	fmt.Printf("Successfully encoded %s to %s\n", *inputFile, *outputFile)
}
