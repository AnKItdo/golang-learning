package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	allowedDir = "valut"
	maxSize    = 1024 * 1024
)

// Custom type error

type FileError struct {
	Code    string
	Path    string
	Message string
}

func (e *FileError) Error() string {
	return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Path)
}

//  Setup

func setupVault() error {
	if err := os.Mkdir(allowedDir, 0755); err != nil {
		return err
	}

	files := map[string]string{
		"users.txt": "alice\nbob\ncharlie\n",
		"notes.txt": "Remember to rotate passwords.\nReview access logs weekly.\n",
		"empty.txt": "",
	}

	for name, content := range files {
		path := filepath.Join(allowedDir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return fmt.Errorf("setupVault :%w", err)
		}
	}
	return nil
}

// Path validation

func ValidatePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)

	allowedAbs, err := filepath.Abs(allowedDir)
	if err != nil {
		return "", fmt.Errorf("validatePath: could not resolve allowed dir: %w", err)
	}

	targetAbs, err := filepath.Abs(cleanPath)
	if err != nil {
		return "",
			fmt.Errorf("ValidatePath: could not resolve target: %w", err)
	}

	allowedPrefix := allowedAbs + string(os.PathSeparator)
	if targetAbs != allowedAbs && !strings.HasPrefix(targetAbs, allowedPrefix) {
		return "", &FileError{
			Code:    "ACESS_DENIED",
			Path:    path,
			Message: "Path traversal attempt blocked",
		}
	}
	return cleanPath, nil

}

// Logging

func logAccess(filename string, success bool, msg string) {
	f, err := os.OpenFile(
		"access.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0600,
	)
	if err != nil {
		fmt.Println("log error: ", err)
		return
	}
	defer f.Close()

	status := "OK"
	if !success {
		status = "FAIL"
	}
	fmt.Fprintf(f, "[%s] %s -%s\n", status, filename, msg)
}

// counts non-empty lines only

func countLines(lines []string) int {
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// checksum SHA-256

func checksum(lines []string) string {
	joined := strings.Join(lines, "\n")
	hash := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(hash[:])
}

func SafeRead(path string) ([]string, error) {
	validPath, err := ValidatePath(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(validPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &FileError{
				Code:    "NOT_FOUND",
				Path:    path,
				Message: "file does not exist",
			}
		}
		return nil, fmt.Errorf("safeRead stat: %w", err)
	}

	if info.Size() > maxSize {
		return nil, &FileError{
			Code:    "TOO_LARGE",
			Path:    path,
			Message: fmt.Sprintf("file is %d bytes, limit is %d", info.Size(), maxSize),
		}
	}

	// Open and Read
	f, err := os.Open(validPath)
	if err != nil {
		return nil, fmt.Errorf("safeRead open :%w", err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("safeRead Scan: %w", err)
	}

	// Reject empty files
	if countLines(lines) == 0 {
		return nil, &FileError{
			Code:    "EMPTY",
			Path:    path,
			Message: "file has no content",
		}
	}
	return lines, nil
}

func main() {
	fmt.Println("=========Secure File Reader ==========\n")

	if err := setupVault(); err != nil {
		fmt.Println("x Startup error:", err)
		os.Exit(1)
	}

	// test cases
	tests := []string{
		filepath.Join(allowedDir, "users.txt"),
		filepath.Join(allowedDir, "notes.txt"),
		filepath.Join(allowedDir, "empty.txt"),
		"../etc/passwd",
	}

	for i, file := range tests {
		fmt.Printf("[%d] Reading: %s\n", i+1, file)

		lines, err := SafeRead(file)
		if err != nil {

			var fe *FileError
			if errors.As(err, &fe) {
				fmt.Printf(" X [%s] %s\n", fe.Code, fe.Message)
				logAccess(filepath.Base(file), false, fe.Code)
			} else {
				fmt.Printf(" Unexpected error %v\n", err)
				logAccess(filepath.Base(file), false, "UNEXPECTED_ERROR")
			}
			fmt.Println()
			continue
		}

		// Success Path
		count := countLines(lines)
		cs := checksum(lines)

		fmt.Printf(" Lines :%d\n", count)
		fmt.Printf(" Content :%s\n", strings.Join(lines, ", "))
		fmt.Printf(" Checksum: %s\n\n", cs)

		logAccess(filepath.Base(file), true, fmt.Sprintf("read %d lines | SHA256: %s", count, cs[:12]+"..."))
	}

	fmt.Println("-----access.log written----")

	logData, err := os.ReadFile("access.log")
	if err == nil {
		fmt.Println(string(logData))
	}
}
