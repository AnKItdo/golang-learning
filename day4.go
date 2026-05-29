package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// isValidIP checks that an IP has exactly 4 parts, each a number 0-255
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".") // split "1.2.3.4" → ["1","2","3","4"]
	if len(parts) != 4 {
		return false // not enough or too many octets
	}
	for _, part := range parts {
		n, err := strconv.Atoi(part) // convert "192" → 192
		if err != nil {
			return false // wasn't a number at all
		}
		if n < 0 || n > 255 {
			return false // out of valid IP range
		}
	}
	return true
}

// isPrivateIP warns if someone is blocking their own internal network
func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.")
}

// blockIP adds the ip and reason into the map
func blockIP(bl map[string]string, ip, reason string) {
	bl[ip] = reason // maps are passed by reference — this modifies the original
}

// unblockIP removes an IP from the map — returns false if it wasn't there
func unblockIP(bl map[string]string, ip string) bool {
	_, exists := bl[ip] // two-value lookup: value, exists
	if !exists {
		return false
	}
	delete(bl, ip) // built-in delete function for maps
	return true
}

// isBlocked returns whether the IP is blocked and the reason why
func isBlocked(bl map[string]string, ip string) (bool, string) {
	reason, exists := bl[ip] // two-value map lookup
	if !exists {
		return false, ""
	}
	return true, reason
}

// listBlocked prints every IP and its reason with a total count
func listBlocked(bl map[string]string) {
	fmt.Printf("\nBlocked IPs (%d):\n", len(bl))
	if len(bl) == 0 {
		fmt.Println("  (none)")
		return
	}
	for ip, reason := range bl {
		fmt.Printf("  %-18s → %s\n", ip, reason) // %-18s = left-aligned, 18 chars wide
	}
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	// map literal — initialize with data in one step
	blocklist := map[string]string{
		"1.2.3.4": "port scan",
		"5.6.7.8": "brute force",
		"9.9.9.9": "malware C2",
	}

	// audit log — a slice that records every action
	auditLog := []string{}

	fmt.Println("=== IP Blocklist Manager ===")

	for { // infinite loop — only exits on case "5"
		fmt.Println("\n1. Block IP")
		fmt.Println("2. Unblock IP")
		fmt.Println("3. Check IP")
		fmt.Println("4. List all blocked IPs")
		fmt.Println("5. Quit")
		fmt.Println("6. Audit log")
		fmt.Print("\nChoice: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {

		case "1": // BLOCK
			fmt.Print("Enter IP to block: ")
			ip, _ := reader.ReadString('\n')
			ip = strings.TrimSpace(ip)

			if !isValidIP(ip) {
				fmt.Println("Invalid IP format.")
				break // break exits the switch case, not the for loop
			}

			if isPrivateIP(ip) {
				fmt.Println("Warning: blocking a private IP range")
			}

			fmt.Print("Enter reason: ")
			reason, _ := reader.ReadString('\n')
			reason = strings.TrimSpace(reason)

			blockIP(blocklist, ip, reason)
			fmt.Printf("%s blocked — %s\n", ip, reason)

			// append action to audit log
			auditLog = append(auditLog, fmt.Sprintf("BLOCKED %s — %s", ip, reason))

		case "2": // UNBLOCK
			fmt.Print("Enter IP to unblock: ")
			ip, _ := reader.ReadString('\n')
			ip = strings.TrimSpace(ip)

			if unblockIP(blocklist, ip) {
				fmt.Printf("%s has been unblocked.\n", ip)
				auditLog = append(auditLog, fmt.Sprintf("UNBLOCKED %s", ip))
			} else {
				fmt.Printf("%s was not in the blocklist.\n", ip)
			}

		case "3": // CHECK
			fmt.Print("Enter IP to check: ")
			ip, _ := reader.ReadString('\n')
			ip = strings.TrimSpace(ip)

			blocked, reason := isBlocked(blocklist, ip)
			if blocked {
				fmt.Printf("BLOCKED — reason: %s\n", reason)
			} else {
				fmt.Printf("%s is not blocked.\n", ip)
			}

		case "4": // LIST
			listBlocked(blocklist)

		case "5": // QUIT
			fmt.Println("Exiting.")
			os.Exit(0)

		case "6": // AUDIT LOG
			fmt.Printf("\nAudit Log (%d entries):\n", len(auditLog))
			if len(auditLog) == 0 {
				fmt.Println("  (no actions yet)")
			}
			for i, entry := range auditLog {
				fmt.Printf("  %d. %s\n", i+1, entry)
			}

		default:
			fmt.Println("Invalid choice — enter 1 to 6.")
		}
	}
}
