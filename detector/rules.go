package detector

import (
	"net"
	"strings"

	"github.com/user/email_spoof_detection/models"
)

// Rule represents a single spoofing detection rule
type Rule struct {
	Name        string
	Description string
	Weight      int // Weight of this rule in the overall score
	CheckFunc   func(*models.Email) (bool, string)
}

// Rules returns a slice of all spoofing detection rules
func Rules() []Rule {
	return []Rule{
		{
			Name:        "inconsistent_from_reply_to",
			Description: "From and Reply-To domains don't match",
			Weight:      3,
			CheckFunc:   checkFromReplyToDomainMismatch,
		},
		{
			Name:        "inconsistent_from_return_path",
			Description: "From and Return-Path domains don't match",
			Weight:      3,
			CheckFunc:   checkFromReturnPathDomainMismatch,
		},
		{
			Name:        "missing_spf",
			Description: "Domain doesn't have SPF record",
			Weight:      2,
			CheckFunc:   checkMissingSPF,
		},
		{
			Name:        "suspicious_from_domain",
			Description: "From domain is suspicious (lookalike domain)",
			Weight:      4,
			CheckFunc:   checkSuspiciousFromDomain,
		},
		{
			Name:        "multiple_from_headers",
			Description: "Email contains multiple From headers",
			Weight:      5,
			CheckFunc:   checkMultipleFromHeaders,
		},
		{
			Name:        "suspicious_received_chain",
			Description: "Suspicious Received headers chain",
			Weight:      2,
			CheckFunc:   checkSuspiciousReceivedChain,
		},
	}
}

// checkFromReplyToDomainMismatch checks if From and Reply-To domains don't match
func checkFromReplyToDomainMismatch(email *models.Email) (bool, string) {
	if email.From == nil || email.ReplyTo == nil {
		return false, ""
	}

	fromDomain := models.GetDomain(email.From)
	replyToDomain := models.GetDomain(email.ReplyTo)

	if fromDomain != "" && replyToDomain != "" && fromDomain != replyToDomain {
		return true, "From domain (" + fromDomain + ") doesn't match Reply-To domain (" + replyToDomain + ")"
	}

	return false, ""
}

// checkFromReturnPathDomainMismatch checks if From and Return-Path domains don't match
func checkFromReturnPathDomainMismatch(email *models.Email) (bool, string) {
	if email.From == nil || email.ReturnPath == "" {
		return false, ""
	}

	fromDomain := models.GetDomain(email.From)
	
	// Extract domain from Return-Path
	returnPathParts := strings.Split(email.ReturnPath, "@")
	if len(returnPathParts) != 2 {
		return false, ""
	}
	returnPathDomain := returnPathParts[1]

	if fromDomain != "" && returnPathDomain != "" && fromDomain != returnPathDomain {
		return true, "From domain (" + fromDomain + ") doesn't match Return-Path domain (" + returnPathDomain + ")"
	}

	return false, ""
}

// checkMissingSPF checks if the domain has an SPF record
func checkMissingSPF(email *models.Email) (bool, string) {
	if email.From == nil {
		return false, ""
	}

	fromDomain := models.GetDomain(email.From)
	if fromDomain == "" {
		return false, ""
	}

	// Look up TXT records for the domain
	txtRecords, err := net.LookupTXT(fromDomain)
	if err != nil {
		// DNS lookup error, can't determine if SPF exists
		return false, ""
	}

	// Check if any of the TXT records is an SPF record
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			return false, ""
		}
	}

	return true, "Domain " + fromDomain + " doesn't have an SPF record"
}

// checkSuspiciousFromDomain checks for lookalike domains
func checkSuspiciousFromDomain(email *models.Email) (bool, string) {
	if email.From == nil {
		return false, ""
	}

	fromDomain := models.GetDomain(email.From)
	if fromDomain == "" {
		return false, ""
	}

	// List of common domains that might be spoofed
	commonDomains := map[string]bool{
		"gmail.com":      true,
		"yahoo.com":      true,
		"outlook.com":    true,
		"hotmail.com":    true,
		"microsoft.com":  true,
		"apple.com":      true,
		"amazon.com":     true,
		"facebook.com":   true,
		"paypal.com":     true,
		"wellsfargo.com": true,
		"bankofamerica.com": true,
		"chase.com":      true,
	}

	// Check for lookalike domains (simple check for demonstration)
	for domain := range commonDomains {
		if fromDomain != domain && isSimilarDomain(fromDomain, domain) {
			return true, "From domain (" + fromDomain + ") looks similar to " + domain
		}
	}

	return false, ""
}

// isSimilarDomain checks if two domains are suspiciously similar
func isSimilarDomain(domain1, domain2 string) bool {
	// Simple check: domain1 contains domain2 but is not equal to it
	if domain1 != domain2 && strings.Contains(domain1, strings.Replace(domain2, ".", "", 1)) {
		return true
	}

	// Check for common typosquatting patterns
	typos := []string{
		strings.Replace(domain2, ".", "-", 1),
		strings.Replace(domain2, ".", "", 1),
		"mail-" + domain2,
		domain2 + "-secure",
		strings.Replace(domain2, "m", "rn", 1), // "m" to "rn"
	}

	for _, typo := range typos {
		if domain1 == typo {
			return true
		}
	}

	return false
}

// checkMultipleFromHeaders checks if there are multiple From headers
func checkMultipleFromHeaders(email *models.Email) (bool, string) {
	fromHeaders := email.GetAllHeaderValues("From")
	if len(fromHeaders) > 1 {
		return true, "Email contains multiple From headers"
	}
	return false, ""
}

// checkSuspiciousReceivedChain checks for suspicious patterns in Received headers
func checkSuspiciousReceivedChain(email *models.Email) (bool, string) {
	receivedHeaders := email.GetAllHeaderValues("Received")
	
	if len(receivedHeaders) == 0 {
		return true, "Email doesn't have any Received headers"
	}
	
	// Check for suspicious patterns in Received headers
	for _, header := range receivedHeaders {
		header = strings.ToLower(header)
		
		// Check for suspicious IP addresses or domains
		suspiciousPatterns := []string{
			"unknown", "localhost", "127.0.0.1", "192.168.", "10.0.", "172.16.",
		}
		
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(header, pattern) {
				return true, "Suspicious pattern found in Received headers: " + pattern
			}
		}
	}
	
	return false, ""
}
