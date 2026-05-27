package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Print("Enter your password: ")
	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	// ✓ Check banned FIRST — before any other rule
	bannedPasswords := []string{
		"password123", "123456", "qwerty", "admin", "letmein",
	}
	for _, banned := range bannedPasswords {
		if password == banned {
			fmt.Println("Verdict: Weak — this password is on the banned list")
			return
		}
	}

	// ✓ Collect all signals — don't exit early
	longEnough := len(password) >= 8

	hasDigit := false
	hasUpper := false
	hasSpecial := false
	specialChars := "!@#$%^&*"

	for _, ch := range password {
		switch {
		case ch >= '0' && ch <= '9':
			hasDigit = true
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case strings.ContainsRune(specialChars, ch):
			hasSpecial = true
		}
	}

	// ✓ Print one clean verdict at the end
	fmt.Printf("\nLength ≥8:  %v\nHas digit:  %v\nHas upper:  %v\nHas special: %v\n\n",
		longEnough, hasDigit, hasUpper, hasSpecial)

	switch {
	case !longEnough:
		fmt.Println("Verdict: Weak — too short")
	case !hasDigit || !hasUpper:
		fmt.Println("Verdict: Medium — missing digit or uppercase")
	case !hasSpecial:
		fmt.Println("Verdict: Strong")
	default:
		fmt.Println("Verdict: Very Strong")
	}
}
