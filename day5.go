package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ─── Structs ────────────────────────────────────────────────────────────────

// LoginRecord tracks WHERE and WHETHER a login succeeded
// This is a nested struct — User embeds it as a field
type LoginRecord struct {
	IP        string
	Success   bool
	Timestamp string // simplified — Day 9 we'll use time.Time
}

type User struct {
	Username    string
	Password    string
	Role        string
	IsLocked    bool
	FailedTries int
	LastLogin   LoginRecord // nested struct as a field
}

// ─── Methods ────────────────────────────────────────────────────────────────

// Describe — value receiver: only reads, never writes
func (u User) Describe() string {
	return fmt.Sprintf(
		"Username: %-10s | Role: %-8s | Locked: %-5t | Failed: %d",
		u.Username, u.Role, u.IsLocked, u.FailedTries,
	)
}

// IsAdmin — value receiver: read-only check
func (u User) IsAdmin() bool {
	return u.Role == "admin"
}

// Lock — pointer receiver: modifies the struct
func (u *User) Lock() {
	u.IsLocked = true
}

// Unlock — pointer receiver: modifies the struct
func (u *User) Unlock() {
	u.IsLocked = false
	u.FailedTries = 0
}

// RecordLogin — takes IP so we know WHERE the attempt came from
// This is what your version was missing
func (u *User) RecordLogin(ip string, success bool) {
	// always record the last login attempt with full context
	u.LastLogin = LoginRecord{
		IP:        ip,
		Success:   success,
		Timestamp: "2024-01-15 09:32", // hardcoded for now — Day 9 uses time.Now()
	}

	if success {
		u.FailedTries = 0 // reset on success
		return
	}

	// failed login
	u.FailedTries++
	if u.FailedTries >= 3 {
		u.Lock() // auto-lock after 3 failures
	}
}

// ChangePassword — stretch goal
// Returns an error so the caller decides what to do with it
func (u *User) ChangePassword(oldPassword, newPassword string) error {
	if u.Password != oldPassword {
		return fmt.Errorf("incorrect current password") // never say which field was wrong
	}
	u.Password = newPassword
	return nil
}

// ─── Functions ──────────────────────────────────────────────────────────────

// findUser — returns a pointer so changes affect the original slice
// KEY: use `for i := range` NOT `for _, u := range`
// `for _, u` gives you a copy — &u would point to the copy, not the real element
func findUser(users []User, username string) *User {
	for i := range users {
		if users[i].Username == username {
			return &users[i] // address of the actual element in the slice
		}
	}
	return nil // not found
}

// adminUnlock — enforces role-based access control (RBAC)
// Only an admin actor can unlock a target account
func adminUnlock(actor *User, target *User) {
	// nil checks — defensive programming, always guard pointer params
	if actor == nil || target == nil {
		fmt.Println(" Invalid user reference")
		return
	}

	if !actor.IsAdmin() {
		fmt.Printf(" Permission denied — %s is not an admin\n", actor.Username)
		return
	}

	target.Unlock()
	fmt.Printf(" %s unlocked %s's account\n", actor.Username, target.Username)
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	reader := bufio.NewReader(os.Stdin)

	// slice of User structs — pre-loaded with 3 users
	users := []User{
		{Username: "admin", Password: "Admin@999", Role: "admin"},
		{Username: "alice", Password: "analyst123", Role: "analyst"},
		{Username: "mallory", Password: "guest123", Role: "guest"},
	}

	// ── 1. Print all users ──────────────────────────────────────────────────
	fmt.Println("=== User Record System ===\n")
	fmt.Println("All Users:")
	for _, u := range users { // value copy is fine here — Describe() is value receiver
		fmt.Println(" ", u.Describe())
	}

	// ── 2. Simulate 3 failed logins for alice ───────────────────────────────
	fmt.Println("\nSimulating 3 failed logins for alice...")

	alice := findUser(users, "alice")
	if alice == nil {
		fmt.Println("User not found")
		os.Exit(1)
	}

	for i := 1; i <= 3; i++ {
		alice.RecordLogin("192.168.1.5", false) // IP tracked on every attempt
		fmt.Printf("  Attempt %d — FailedTries: %d | Locked: %v\n",
			i, alice.FailedTries, alice.IsLocked)
	}

	// show what was recorded on the last login
	fmt.Printf("\nalice's last login → IP: %s | Success: %v | Time: %s\n",
		alice.LastLogin.IP,
		alice.LastLogin.Success,
		alice.LastLogin.Timestamp,
	)

	// ── 3. Role-based unlock ────────────────────────────────────────────────
	fmt.Println("\n=== Admin Unlock ===")

	admin := findUser(users, "admin")
	mallory := findUser(users, "mallory")

	// non-admin tries to unlock
	adminUnlock(mallory, alice)

	// admin unlocks
	adminUnlock(admin, alice)
	fmt.Println(" ", alice.Describe())

	// ── 4. Change password ──────────────────────────────────────────────────
	fmt.Println("\n=== Password Change ===")

	// wrong old password
	err := alice.ChangePassword("wrongpass", "newpass123")
	if err != nil {
		fmt.Println(" Error:", err)
	}

	// correct old password
	err = alice.ChangePassword("analyst123", "newpass123")
	if err != nil {
		fmt.Println(" Error:", err)
	} else {
		fmt.Println(" Password changed successfully")
	}

	// ── 5. Interactive user search ──────────────────────────────────────────
	fmt.Print("\nEnter username to look up: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	found := findUser(users, input)
	if found == nil {
		fmt.Printf(" User '%s' not found\n", input)
	} else {
		fmt.Println("User found", found.Describe())
	}
}
