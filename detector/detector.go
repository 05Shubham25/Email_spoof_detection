package detector

import (
	"log"
	"net"
	"strings"

	"github.com/user/email_spoof_detection/models"
)

// SpoofDetector implements email spoofing detection logic
type SpoofDetector struct {
	rules []Rule
}

// NewSpoofDetector creates a new instance of SpoofDetector
func NewSpoofDetector() *SpoofDetector {
	return &SpoofDetector{
		rules: Rules(),
	}
}

// Analyze checks an email for signs of spoofing
func (d *SpoofDetector) Analyze(email *models.Email) *models.AnalysisResult {
	result := &models.AnalysisResult{
		IsSpoofed: false,
		Reasons:   []string{},
		Score:     0,
	}

	// Apply each rule
	for _, rule := range d.rules {
		triggered, reason := rule.CheckFunc(email)
		if triggered {
			result.Score += rule.Weight
			result.Reasons = append(result.Reasons, reason)
		}
	}

	// Check SPF, DKIM, and DMARC if From domain is available
	if email.From != nil {
		fromDomain := models.GetDomain(email.From)
		if fromDomain != "" {
			// Check SPF
			spfResult := d.checkSPF(email, fromDomain)
			if spfResult != "" {
				result.Score += 3
				result.Reasons = append(result.Reasons, spfResult)
			}

			// Check DKIM
			dkimResult := d.checkDKIM(email, fromDomain)
			if dkimResult != "" {
				result.Score += 3
				result.Reasons = append(result.Reasons, dkimResult)
			}

			// Check DMARC
			dmarcResult := d.checkDMARC(email, fromDomain)
			if dmarcResult != "" {
				result.Score += 2
				result.Reasons = append(result.Reasons, dmarcResult)
			}
		}
	}

	// Determine if the email is spoofed based on the score
	// A score of 5 or higher indicates spoofing
	if result.Score >= 5 {
		result.IsSpoofed = true
	}

	return result
}

// checkSPF verifies if the email passes SPF checks
func (d *SpoofDetector) checkSPF(email *models.Email, domain string) string {
	// In a real implementation, this would check the sending IP against the domain's SPF record
	// For this example, we'll just check if the domain has an SPF record
	
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("SPF lookup error for domain %s: %v", domain, err)
		return "SPF lookup failed for domain " + domain
	}

	// Check if any of the TXT records is an SPF record
	spfRecord := ""
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			spfRecord = record
			break
		}
	}

	if spfRecord == "" {
		return "Domain " + domain + " doesn't have an SPF record"
	}

	// In a real implementation, we would check if the sending IP is allowed by the SPF record
	// For this example, we'll just check if the SPF record has a restrictive policy
	if strings.Contains(spfRecord, "-all") {
		// Domain has a strict SPF policy
		// In a real implementation, we would check if the sending IP is allowed
		return ""
	} else if strings.Contains(spfRecord, "~all") {
		// Domain has a soft-fail SPF policy
		return ""
	} else if strings.Contains(spfRecord, "?all") {
		// Domain has a neutral SPF policy
		return "Domain " + domain + " has a neutral SPF policy"
	} else {
		// Domain has a permissive SPF policy
		return "Domain " + domain + " has a permissive SPF policy"
	}
}

// checkDKIM verifies if the email has a valid DKIM signature
func (d *SpoofDetector) checkDKIM(email *models.Email, domain string) string {
	// In a real implementation, this would verify the DKIM signature
	// For this example, we'll just check if the email has a DKIM-Signature header
	
	if !email.HasHeader("DKIM-Signature") {
		return "Email doesn't have a DKIM signature"
	}

	// In a real implementation, we would verify the DKIM signature
	// For this example, we'll just check if the DKIM signature contains the From domain
	dkimSignature := email.GetHeaderValue("DKIM-Signature")
	if !strings.Contains(dkimSignature, domain) {
		return "DKIM signature domain doesn't match From domain"
	}

	return ""
}

// checkDMARC verifies if the domain has a DMARC policy
func (d *SpoofDetector) checkDMARC(email *models.Email, domain string) string {
	// In a real implementation, this would check the domain's DMARC policy
	// For this example, we'll just check if the domain has a DMARC record
	
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		log.Printf("DMARC lookup error for domain %s: %v", dmarcDomain, err)
		return "DMARC lookup failed for domain " + domain
	}

	// Check if any of the TXT records is a DMARC record
	dmarcRecord := ""
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			dmarcRecord = record
			break
		}
	}

	if dmarcRecord == "" {
		return "Domain " + domain + " doesn't have a DMARC record"
	}

	// In a real implementation, we would check the DMARC policy
	// For this example, we'll just check if the DMARC policy is restrictive
	if strings.Contains(dmarcRecord, "p=reject") {
		// Domain has a strict DMARC policy
		return ""
	} else if strings.Contains(dmarcRecord, "p=quarantine") {
		// Domain has a moderate DMARC policy
		return ""
	} else if strings.Contains(dmarcRecord, "p=none") {
		// Domain has a monitoring-only DMARC policy
		return "Domain " + domain + " has a monitoring-only DMARC policy"
	} else {
		// Domain has an unknown DMARC policy
		return "Domain " + domain + " has an unknown DMARC policy"
	}
}
