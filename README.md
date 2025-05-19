# Email Spoofing Detection

A Go application that identifies and flags emails with misleading sender information (spoofing).

## Features

- Parse email headers to extract sender information
- Check for inconsistencies between header fields (From, Reply-To, Return-Path)
- Validate email domains against SPF, DKIM, and DMARC records
- Flag suspicious emails based on predefined rules
- Simple command-line interface

## Usage

```bash
# Build the application
go build -o spoof_detector

# Run with a sample email file
./spoof_detector -file sample_email.eml

# Or process multiple email files
./spoof_detector -dir /path/to/emails/
```

## How It Works

Email spoofing detection works by analyzing email headers and validating sender information against DNS records. The application checks:

1. Consistency between From, Reply-To, and Return-Path headers
2. SPF (Sender Policy Framework) records to verify if the sending server is authorized
3. DKIM (DomainKeys Identified Mail) signatures for email authenticity
4. DMARC (Domain-based Message Authentication, Reporting, and Conformance) policies

## Requirements

- Go 1.20 or higher
- Internet connection for DNS lookups
