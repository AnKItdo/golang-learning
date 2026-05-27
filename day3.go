package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

func hashMD5(input string) string {
	hash := md5.Sum([]byte(input))
	return fmt.Sprintf("%x", hash)
}

func hashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)
}

func compareHashes(a, b string) bool {
	return a == b
}

func detectWeakHash(hash string) bool {
	return len(hash) == 32
}

func hashWithSalt(input, salt string) string {
	return hashSHA256(salt + input)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("===================Hash Utility============================")

	fmt.Println("Enter a string to hash")
	firstInput, _ := reader.ReadString('\n')
	firstInput = strings.TrimSpace(firstInput)

	// store hash value

	md5Hash := hashMD5(firstInput)
	sha256Hash := hashSHA256(firstInput)

	fmt.Println("\n MD5 hash is %s\n", md5Hash)
	fmt.Println("\n SHA256 hash is %s\n", sha256Hash)

	if detectWeakHash(md5Hash) {
		fmt.Println("MD5 is weak - do not use for security")
	}

	fmt.Println("Enter second string to compare SHA-256")
	secondInput, _ := reader.ReadString('\n')
	secondInput = strings.TrimSpace(secondInput)

	secondSHA256 := hashSHA256(secondInput)

	if compareHashes(sha256Hash, secondSHA256) {
		fmt.Println("MATCHED HASHES")
	} else {
		fmt.Println("NOT MATCHED")
	}

	// Salted Hash
	fmt.Println("Enter your Salt")
	salt, _ := reader.ReadString('\n')
	salt = strings.TrimSpace(salt)

	fmt.Printf("Salted SHA-256: %s\n", hashWithSalt(firstInput, salt))
}
