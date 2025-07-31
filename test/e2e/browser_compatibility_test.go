//go:build browser

package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
	"github.com/tebeka/selenium/firefox"
)

type BrowserMatrix struct {
	Metadata BrowserMetadata `json:"metadata"`
	Results  []TestResult    `json:"results"`
}

type BrowserMetadata struct {
	Timestamp string            `json:"timestamp"`
	Browsers  map[string]string `json:"browsers"`
}

type TestResult struct {
	Browser     string `json:"browser"`
	Certificate string `json:"certificate"`
	Status      string `json:"status"`
}

var certificateTypes = []string{
	"rsa2048-sha256", "rsa2048-sha512",
	"rsa3072-sha256", "rsa3072-sha512",
	"rsa4096-sha256", "rsa4096-sha512",
	"ecp256-sha256", "ecp256-sha512",
	"ecp384-sha256", "ecp384-sha512",
	"ecp521-sha256", "ecp521-sha512",
	"ed25519-sha256", "ed25519-sha512",
}

func TestBrowserCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser compatibility test in short mode")
	}

	// Get absolute paths to local CA files
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	localCACert := filepath.Join(filepath.Dir(filepath.Dir(wd)), "test", "local_ca", "ca.crt")
	localCAKey := filepath.Join(filepath.Dir(filepath.Dir(wd)), "test", "local_ca", "ca.key")

	// Setup test environment
	testDir := setupTestEnvironment(t, localCACert, localCAKey)
	defer cleanupTestEnvironment(testDir)

	// Start HTTPS server with certificate rotation
	serverPort := "8443"
	server := startHTTPSServer(t, testDir, serverPort)
	defer server.Close()

	// Initialize results
	matrix := BrowserMatrix{
		Metadata: BrowserMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Browsers:  make(map[string]string),
		},
		Results: []TestResult{},
	}

	// Test with curl first (baseline)
	t.Run("curl", func(t *testing.T) {
		results := testWithCurl(t, testDir, serverPort)
		matrix.Results = append(matrix.Results, results...)
		matrix.Metadata.Browsers["curl"] = getCurlVersion()
	})

	// Test with browsers if available
	if runtime.GOOS == "darwin" {
		// Test Chrome
		if isApplicationInstalled("Google Chrome") {
			t.Run("chrome", func(t *testing.T) {
				results := testWithChrome(t, testDir, serverPort)
				matrix.Results = append(matrix.Results, results...)
				matrix.Metadata.Browsers["chromium"] = getChromeVersion()
			})
		}

		// Test Firefox
		if isApplicationInstalled("Firefox") {
			t.Run("firefox", func(t *testing.T) {
				results := testWithFirefox(t, testDir, serverPort)
				matrix.Results = append(matrix.Results, results...)
				matrix.Metadata.Browsers["firefox"] = getFirefoxVersion()
			})
		}

		// Test Safari/WebKit
		t.Run("safari", func(t *testing.T) {
			results := testWithSafari(t, testDir, serverPort)
			matrix.Results = append(matrix.Results, results...)
			matrix.Metadata.Browsers["webkit"] = getSafariVersion()
		})
	}

	// Write results to JSON file (relative to project root)
	outputPath := filepath.Join(filepath.Dir(filepath.Dir(wd)), "docs", "browser-matrix-local.json")
	writeResults(t, matrix, outputPath)

	// Print summary
	printSummary(matrix)
}

func setupTestEnvironment(t *testing.T, caCertPath, caKeyPath string) string {
	t.Helper()

	testDir := t.TempDir()

	// Use the same binary that other e2e tests use
	if reactorCABin == "" {
		t.Fatal("reactorCABin is empty - TestMain may not have run")
	}

	// Check that CA cert and key files exist
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Fatalf("CA certificate file not found: %s", caCertPath)
	}
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Fatalf("CA private key file not found: %s", caKeyPath)
	}

	// Initialize ReactorCA in test directory
	cmd := exec.Command(reactorCABin, "init")
	cmd.Dir = testDir
	cmd.Env = append(os.Environ(), "REACTOR_CA_PASSWORD=test-password-123")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to initialize CA: %v\nOutput: %s", err, output)
	}

	// Create hosts configuration for all certificate types
	createHostsConfig(t, testDir)

	// Import the external CA
	cmd = exec.Command(reactorCABin, "ca", "import", "--cert", caCertPath, "--key", caKeyPath)
	cmd.Dir = testDir
	cmd.Env = append(os.Environ(), "REACTOR_CA_PASSWORD=test-password-123")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to import CA: %v\nOutput: %s", err, output)
	}

	// Issue all certificates
	cmd = exec.Command(reactorCABin, "host", "issue", "--all")
	cmd.Dir = testDir
	cmd.Env = append(os.Environ(), "REACTOR_CA_PASSWORD=test-password-123")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to issue certificates: %v\nOutput: %s", err, output)
	}

	return testDir
}

func createHostsConfig(t *testing.T, testDir string) {
	t.Helper()

	configContent := "hosts:\n"

	for _, certType := range certificateTypes {
		parts := strings.Split(certType, "-")
		keyAlgo := strings.ToUpper(parts[0])
		hashAlgo := strings.ToUpper(parts[1])

		configContent += fmt.Sprintf(`  %s:
    alternative_names:
      dns:
        - %s.localhost
        - 127.0.0.1
      ip:
        - 127.0.0.1
        - ::1
    validity:
      years: 1
    key_algorithm: %s
    hash_algorithm: %s
`, certType, certType, keyAlgo, hashAlgo)
	}

	configPath := filepath.Join(testDir, "config", "hosts.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write hosts config: %v", err)
	}
}

func startHTTPSServer(t *testing.T, testDir, port string) *http.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `<!DOCTYPE html>
<html>
<head><title>ReactorCA HTTPS Test</title></head>
<body>
	<h1>HTTPS Working!</h1>
	<p>ReactorCA self-signed certificate is working correctly.</p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// Find matching certificate based on SNI
				certType := strings.TrimSuffix(hello.ServerName, ".localhost")

				certPath := filepath.Join(testDir, "store", "hosts", certType, "cert.crt")
				keyPath := filepath.Join(testDir, "store", "hosts", certType, "cert.key.age")

				// Decrypt private key temporarily
				keyData, err := decryptPrivateKey(testDir, keyPath)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt key for %s: %v", certType, err)
				}

				cert, err := tls.LoadX509KeyPair(certPath, keyData)
				if err != nil {
					return nil, fmt.Errorf("failed to load certificate for %s: %v", certType, err)
				}

				return &cert, nil
			},
		},
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			t.Errorf("HTTPS server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)
	return server
}

func decryptPrivateKey(testDir, keyPath string) (string, error) {
	// Create temporary file for decrypted key
	tmpFile, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// Extract host ID from key path (e.g. store/hosts/web-server/cert.key.age -> web-server)
	pathParts := strings.Split(keyPath, string(filepath.Separator))
	var hostID string
	for i, part := range pathParts {
		if part == "hosts" && i+1 < len(pathParts) {
			hostID = pathParts[i+1]
			break
		}
	}
	if hostID == "" {
		return "", fmt.Errorf("could not extract host ID from path: %s", keyPath)
	}

	// Use ReactorCA's export-key command
	cmd := exec.Command(reactorCABin, "host", "export-key", hostID, "-o", tmpPath)
	cmd.Dir = testDir
	cmd.Env = append(os.Environ(), "REACTOR_CA_PASSWORD=test-password-123")

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("export-key failed: %v", err)
	}

	return tmpPath, nil
}

func testWithCurl(t *testing.T, testDir, port string) []TestResult {
	t.Helper()

	var results []TestResult

	for _, certType := range certificateTypes {
		url := fmt.Sprintf("https://%s.localhost:%s/", certType, port)

		// Use system cert store only (no --cacert flag)
		cmd := exec.Command("curl", "-s", "-f", url)
		output, err := cmd.Output()

		status := "FAIL"
		if err == nil && strings.Contains(string(output), "HTTPS Working!") {
			status = "PASS"
		}

		results = append(results, TestResult{
			Browser:     "curl",
			Certificate: certType,
			Status:      status,
		})
	}

	return results
}

func testWithChrome(t *testing.T, testDir, port string) []TestResult {
	t.Helper()

	var results []TestResult

	// Start Chrome WebDriver
	service, err := selenium.NewChromeDriverService("./chromedriver", 9515)
	if err != nil {
		// Try to use system chromedriver
		service, err = selenium.NewChromeDriverService("chromedriver", 9515)
		if err != nil {
			t.Skipf("ChromeDriver not available: %v", err)
			return results
		}
	}
	defer service.Stop()

	caps := selenium.Capabilities{"browserName": "chrome"}
	caps.AddChrome(chrome.Capabilities{
		Args: []string{
			"--ignore-certificate-errors",
			"--ignore-ssl-errors",
			"--ignore-certificate-errors-spki-list",
			"--allow-running-insecure-content",
			"--disable-extensions",
			"--headless",
		},
	})

	driver, err := selenium.NewRemote(caps, "http://localhost:9515")
	if err != nil {
		t.Skipf("Failed to create Chrome driver: %v", err)
		return results
	}
	defer driver.Quit()

	for _, certType := range certificateTypes {
		url := fmt.Sprintf("https://%s.localhost:%s/", certType, port)

		status := "FAIL"
		err := driver.Get(url)
		if err == nil {
			// Check if page loaded successfully
			title, titleErr := driver.Title()
			if titleErr == nil && strings.Contains(title, "ReactorCA HTTPS Test") {
				status = "PASS"
			}
		}

		results = append(results, TestResult{
			Browser:     "chromium",
			Certificate: certType,
			Status:      status,
		})
	}

	return results
}

func testWithFirefox(t *testing.T, testDir, port string) []TestResult {
	t.Helper()

	var results []TestResult

	// Start Firefox WebDriver
	service, err := selenium.NewGeckoDriverService("./geckodriver", 4444)
	if err != nil {
		service, err = selenium.NewGeckoDriverService("geckodriver", 4444)
		if err != nil {
			t.Skipf("GeckoDriver not available: %v", err)
			return results
		}
	}
	defer service.Stop()

	caps := selenium.Capabilities{"browserName": "firefox"}
	caps.AddFirefox(firefox.Capabilities{
		Binary: "/Applications/Firefox.app/Contents/MacOS/firefox",
		Args:   []string{"--headless"},
		Prefs: map[string]interface{}{
			"security.insecure_connection_text.enabled":          true,
			"security.insecure_field_warning.contextual.enabled": false,
		},
	})

	driver, err := selenium.NewRemote(caps, "http://localhost:4444")
	if err != nil {
		t.Skipf("Failed to create Firefox driver: %v", err)
		return results
	}
	defer driver.Quit()

	for _, certType := range certificateTypes {
		url := fmt.Sprintf("https://%s.localhost:%s/", certType, port)

		status := "FAIL"
		err := driver.Get(url)
		if err == nil {
			title, titleErr := driver.Title()
			if titleErr == nil && strings.Contains(title, "ReactorCA HTTPS Test") {
				status = "PASS"
			}
		}

		results = append(results, TestResult{
			Browser:     "firefox",
			Certificate: certType,
			Status:      status,
		})
	}

	return results
}

func testWithSafari(t *testing.T, testDir, port string) []TestResult {
	t.Helper()

	var results []TestResult

	// Start safaridriver manually
	cmd := exec.Command("/usr/bin/safaridriver", "--port", "4445")
	if err := cmd.Start(); err != nil {
		t.Skipf("Failed to start safaridriver: %v", err)
		return results
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	// Wait for safaridriver to start
	time.Sleep(2 * time.Second)

	// Safari WebDriver configuration
	caps := selenium.Capabilities{"browserName": "safari"}

	driver, err := selenium.NewRemote(caps, "http://localhost:4445")
	if err != nil {
		t.Skipf("Failed to create Safari driver: %v", err)
		return results
	}
	defer driver.Quit()

	for _, certType := range certificateTypes {
		url := fmt.Sprintf("https://%s.localhost:%s/", certType, port)

		status := "FAIL"
		err := driver.Get(url)
		if err == nil {
			// Check if page loaded successfully
			title, titleErr := driver.Title()
			if titleErr == nil && strings.Contains(title, "ReactorCA HTTPS Test") {
				status = "PASS"
			}
		}

		results = append(results, TestResult{
			Browser:     "webkit",
			Certificate: certType,
			Status:      status,
		})
	}

	return results
}

func cleanupTestEnvironment(testDir string) {
	os.RemoveAll(testDir)
}

func writeResults(t *testing.T, matrix BrowserMatrix, outputPath string) {
	t.Helper()

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	data, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal results: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		t.Fatalf("Failed to write results: %v", err)
	}

	t.Logf("Results written to %s", outputPath)
}

func printSummary(matrix BrowserMatrix) {
	fmt.Printf("\n=== Browser Compatibility Test Results ===\n")
	fmt.Printf("Timestamp: %s\n\n", matrix.Metadata.Timestamp)

	browserStats := make(map[string]map[string]int)

	for _, result := range matrix.Results {
		if browserStats[result.Browser] == nil {
			browserStats[result.Browser] = make(map[string]int)
		}
		browserStats[result.Browser][result.Status]++
	}

	for browser, stats := range browserStats {
		version := matrix.Metadata.Browsers[browser]
		pass := stats["PASS"]
		fail := stats["FAIL"]
		total := pass + fail

		fmt.Printf("%s (%s): %d/%d passed (%.1f%%)\n",
			browser, version, pass, total, float64(pass)/float64(total)*100)
	}
}

// Helper functions for version detection
func getCurlVersion() string {
	cmd := exec.Command("curl", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return "unknown"
}

func getChromeVersion() string {
	cmd := exec.Command("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	version := strings.TrimSpace(string(output))
	return strings.TrimPrefix(version, "Google Chrome ")
}

func getFirefoxVersion() string {
	cmd := exec.Command("/Applications/Firefox.app/Contents/MacOS/firefox", "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	version := strings.TrimSpace(string(output))
	return strings.TrimPrefix(version, "Mozilla Firefox ")
}

func getSafariVersion() string {
	return "unknown"
}

func isApplicationInstalled(appName string) bool {
	_, err := os.Stat(fmt.Sprintf("/Applications/%s.app", appName))
	return err == nil
}
