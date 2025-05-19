package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/user/email_spoof_detection/detector"
	"github.com/user/email_spoof_detection/utils"
)

func main() {
	// Define command line flags
	filePath := flag.String("file", "", "Path to a single email file to analyze")
	dirPath := flag.String("dir", "", "Path to a directory of email files to analyze")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	// Configure logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(0)
	}

	// Validate input
	if *filePath == "" && *dirPath == "" {
		log.Fatal("Error: You must specify either -file or -dir flag")
	}

	// Process a single file
	if *filePath != "" {
		processEmailFile(*filePath, *verbose)
		return
	}

	// Process a directory of files
	if *dirPath != "" {
		files, err := os.ReadDir(*dirPath)
		if err != nil {
			log.Fatalf("Error reading directory: %v", err)
		}

		for _, file := range files {
			if !file.IsDir() {
				fullPath := filepath.Join(*dirPath, file.Name())
				processEmailFile(fullPath, *verbose)
			}
		}
	}
}

func processEmailFile(filePath string, verbose bool) {
	fmt.Printf("Analyzing email: %s\n", filePath)

	// Read the email file
	emailData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v\n", filePath, err)
		return
	}

	// Parse the email
	email, err := utils.ParseEmail(emailData)
	if err != nil {
		log.Printf("Error parsing email %s: %v\n", filePath, err)
		return
	}

	// Create a detector
	spfDetector := detector.NewSpoofDetector()

	// Analyze the email
	results := spfDetector.Analyze(email)

	// Print results
	if results.IsSpoofed {
		fmt.Printf("⚠️  SPOOFED EMAIL DETECTED: %s\n", filePath)
		for _, reason := range results.Reasons {
			fmt.Printf("  - %s\n", reason)
		}
	} else if verbose {
		fmt.Printf("✓ Email appears legitimate: %s\n", filePath)
	}

	fmt.Println()
}
