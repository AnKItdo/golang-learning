package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	validUsername = "admin"
	validPassword = "GoSecure!"
	maxAttempts   = 3
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("======Secure Login=========")

	for attempts := 1; attempts <= maxAttempts; attempts++ {
		fmt.Print("Enter your username:")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)

		fmt.Print("Enter your password:")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		// track internal which field failed
		wrongUser := username != validUsername
		wrongpass := password != validPassword

		if !wrongUser && wrongpass {
			fmt.Println("\n")
			fmt.Println("Welcome, %s. Access Granted", username)
			fmt.Println("===============================")
			return
		}
		_ = wrongUser
		_ = wrongpass

		remaining := maxAttempts - attempts
		fmt.Println("\n invalid credentials %d attempts remaining \n", remaining)

		switch attempts {
		case 1:
			fmt.Println("Warning please check your credentials")
		case 2:
			fmt.Println("Warning: This is your last attempts \n")
		case 3:

		}
	}
	fmt.Println("\n Account locked. Too many failed attempts")
	os.Exit(1)
}
