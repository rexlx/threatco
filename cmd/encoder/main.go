package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag" // Still need this for the types
	"fmt"
	"io"
	"log"
	"os"

	"github.com/rexlx/threatco/internal"
)

func main() {
	// 1. Create a private FlagSet to ignore global noise from internal
	fs := flag.NewFlagSet("encoder", flag.ExitOnError)

	// 2. Define flags on the private set
	inputFile := fs.String("input", "config.json", "Plaintext JSON config file")
	outputFile := fs.String("output", "config.enc", "Output encrypted file")
	seedFile := fs.String("seed", "", "Path to the seed file")

	// 3. Parse only the arguments passed to this tool
	fs.Parse(os.Args[1:])

	partialKey := os.Getenv("THREATCO_CONFIG_KEY")
	if partialKey == "" || *seedFile == "" {
		fmt.Println("Usage: THREATCO_CONFIG_KEY=xxx ./encoder -seed <file> [-input <file>] [-output <file>]")
		os.Exit(1)
	}

	// 4. Derive Passcode
	f, err := os.Open(*seedFile)
	if err != nil {
		log.Fatalf("Failed to open seed file: %v", err)
	}
	defer f.Close()

	seedHash, err := internal.CalculateSHA256(f)
	if err != nil {
		log.Fatalf("Failed to hash seed file: %v", err)
	}
	passcode := partialKey + seedHash

	// 5. Read Plaintext
	plaintext, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	// 6. Prepare Encryption Components
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	// 7. Derive Key and Initialize Cipher
	key := internal.DeriveKey(passcode, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	// 8. Encrypt and Write Binary: [Salt][Nonce][Ciphertext]
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	out.Write(salt)
	out.Write(nonce)
	out.Write(ciphertext)

	fmt.Printf("Successfully encoded %s to %s\n", *inputFile, *outputFile)
}
