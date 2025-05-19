package models

import (
	"net/mail"
	"strings"
)

// Email represents a parsed email with relevant header information
type Email struct {
	From       *mail.Address
	ReplyTo    *mail.Address
	ReturnPath string
	MessageID  string
	Subject    string
	Body       string
	Headers    map[string][]string
	RawContent []byte
}

// AnalysisResult contains the results of spoofing detection analysis
type AnalysisResult struct {
	IsSpoofed bool
	Reasons   []string
	Score     int // Higher score means higher probability of spoofing
}

// GetDomain extracts the domain part from an email address
func GetDomain(address *mail.Address) string {
	if address == nil {
		return ""
	}
	
	parts := strings.Split(address.Address, "@")
	if len(parts) != 2 {
		return ""
	}
	
	return parts[1]
}

// GetHeaderValue returns the first value of a header field
func (e *Email) GetHeaderValue(name string) string {
	values, exists := e.Headers[name]
	if !exists || len(values) == 0 {
		return ""
	}
	return values[0]
}

// GetAllHeaderValues returns all values of a header field
func (e *Email) GetAllHeaderValues(name string) []string {
	return e.Headers[name]
}

// HasHeader checks if a header exists
func (e *Email) HasHeader(name string) bool {
	_, exists := e.Headers[name]
	return exists
}
