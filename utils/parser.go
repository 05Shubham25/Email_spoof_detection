package utils

import (
	"bytes"
	"errors"
	"io"
	"net/mail"
	"strings"

	"github.com/user/email_spoof_detection/models"
)

// ParseEmail parses raw email data into a structured Email object
func ParseEmail(data []byte) (*models.Email, error) {
	if len(data) == 0 {
		return nil, errors.New("empty email data")
	}

	// Parse the email message
	reader := bytes.NewReader(data)
	msg, err := mail.ReadMessage(reader)
	if err != nil {
		return nil, err
	}

	// Create a new Email object
	email := &models.Email{
		Headers:    msg.Header,
		RawContent: data,
	}

	// Parse From header
	from := msg.Header.Get("From")
	if from != "" {
		fromAddr, err := mail.ParseAddress(from)
		if err == nil {
			email.From = fromAddr
		}
	}

	// Parse Reply-To header
	replyTo := msg.Header.Get("Reply-To")
	if replyTo != "" {
		replyToAddr, err := mail.ParseAddress(replyTo)
		if err == nil {
			email.ReplyTo = replyToAddr
		}
	}

	// Parse Return-Path header
	returnPath := msg.Header.Get("Return-Path")
	if returnPath != "" {
		// Remove the angle brackets if present
		returnPath = strings.TrimPrefix(returnPath, "<")
		returnPath = strings.TrimSuffix(returnPath, ">")
		email.ReturnPath = returnPath
	}

	// Parse Message-ID
	email.MessageID = msg.Header.Get("Message-ID")

	// Parse Subject
	email.Subject = msg.Header.Get("Subject")

	// Read the message body
	body, err := io.ReadAll(msg.Body)
	if err == nil {
		email.Body = string(body)
	}

	return email, nil
}

// ExtractEmailParts extracts the local part and domain from an email address
func ExtractEmailParts(email string) (string, string, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", "", errors.New("invalid email format")
	}
	
	localPart := parts[0]
	domain := parts[1]
	
	return localPart, domain, nil
}
