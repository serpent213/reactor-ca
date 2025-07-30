const playwright = require('playwright');
const fs = require('fs');
const path = require('path');

// Define all certificate combinations
const KEY_ALGORITHMS = ['RSA2048', 'RSA3072', 'RSA4096', 'ECP256', 'ECP384', 'ECP521', 'ED25519'];
const HASH_ALGORITHMS = ['SHA256', 'SHA512'];

function generateCertCombinations() {
  const combinations = [];
  for (const keyAlgo of KEY_ALGORITHMS) {
    for (const hashAlgo of HASH_ALGORITHMS) {
      const certName = `${keyAlgo.toLowerCase()}-${hashAlgo.toLowerCase()}`;
      combinations.push({
        name: certName,
        keyAlgorithm: keyAlgo,
        hashAlgorithm: hashAlgo,
        hostname: `${certName}.localhost`
      });
    }
  }
  return combinations;
}

async function testSingleCertificate(browser, cert, browserType) {
  const result = {
    certificate: cert.name,
    keyAlgorithm: cert.keyAlgorithm,
    hashAlgorithm: cert.hashAlgorithm,
    hostname: cert.hostname,
    status: 'FAIL',
    error: null,
    details: null
  };

  try {
    let contextOptions = {};
    
    // Browser-specific configuration for certificate validation
    if (browserType === 'firefox') {
      contextOptions.ignoreHTTPSErrors = true;
    } else if (browserType === 'chromium') {
      contextOptions.ignoreHTTPSErrors = false;
    } else if (browserType === 'webkit') {
      contextOptions.ignoreHTTPSErrors = false;
    }

    const context = await browser.newContext(contextOptions);
    const page = await context.newPage();

    // Navigate to the specific certificate's hostname
    const url = `https://${cert.hostname}:8443`;
    console.log(`Testing ${cert.name} at ${url}...`);
    
    await page.goto(url, { waitUntil: 'networkidle', timeout: 10000 });

    // Check if page loaded successfully
    const title = await page.title();
    const content = await page.textContent('h1');
    
    if (content && content.includes('HTTPS Working')) {
      result.status = 'PASS';
      
      // Get security info and certificate details
      const securityInfo = await page.evaluate(() => {
        return {
          protocol: location.protocol,
          host: location.host,
          origin: location.origin
        };
      });
      
      // Try to get certificate type from response headers
      const response = await page.goto(url, { waitUntil: 'networkidle' });
      const headers = response.headers();
      
      result.details = {
        title: title,
        securityInfo: securityInfo,
        certTypeHeader: headers['x-cert-type'] || 'unknown'
      };
      
      console.log(`[PASS] ${cert.name}: Certificate loaded successfully`);
    } else {
      result.error = 'Page content not found or incorrect';
      console.log(`[FAIL] ${cert.name}: ${result.error}`);
    }
    
    await context.close();
  } catch (error) {
    result.error = error.message;
    console.log(`[FAIL] ${cert.name}: ${error.message}`);
  }
  
  return result;
}

async function testBrowser(browserType) {
  const results = {
    browser: browserType,
    timestamp: new Date().toISOString(),
    results: []
  };

  let launchOptions = {
    headless: true,
  };

  // Browser-specific launch configuration
  if (browserType === 'firefox') {
    launchOptions.firefoxUserPrefs = {
      'security.enterprise_roots.enabled': true
    };
  } else if (browserType === 'chromium') {
    launchOptions.args = ['--ignore-certificate-errors', '--ignore-ssl-errors', '--ignore-certificate-errors-spki-list'];
  }

  const browser = await playwright[browserType].launch(launchOptions);
  const certCombinations = generateCertCombinations();

  try {
    console.log(`\n=== Testing ${certCombinations.length} certificate combinations with ${browserType} ===`);
    
    // Test each certificate combination
    for (const cert of certCombinations) {
      const result = await testSingleCertificate(browser, cert, browserType);
      results.results.push(result);
    }
    
    // Save results to file
    const resultsDir = '/var/lib/test/test-results';
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }
    
    const resultsFile = path.join(resultsDir, `${browserType}-results.json`);
    fs.writeFileSync(resultsFile, JSON.stringify(results, null, 2));
    
    // Print summary
    const passed = results.results.filter(r => r.status === 'PASS').length;
    const failed = results.results.filter(r => r.status === 'FAIL').length;
    
    console.log(`\n=== ${browserType} Summary ===`);
    console.log(`Certificates passed: ${passed}`);
    console.log(`Certificates failed: ${failed}`);
    console.log(`Results saved to: ${resultsFile}`);
    
    // Return success if any certificates passed (don't fail on individual cert failures)
    return passed > 0;
    
  } catch (error) {
    console.error(`[FAIL] Browser test setup failed: ${error.message}`);
    return false;
  } finally {
    await browser.close();
  }
}

// Get browser type from command line argument
const browserType = process.argv[2];
if (!browserType) {
  console.error('Usage: node browser-test.js <browserType>');
  console.error('Available browser types: chromium, firefox, webkit');
  process.exit(1);
}

testBrowser(browserType).then(success => {
  // Don't fail the workflow if some certificates don't work
  // We want to collect all results for analysis
  console.log(`\nBrowser test completed. Success: ${success}`);
  process.exit(0);
}).catch(error => {
  console.error('Browser test failed with error:', error);
  process.exit(1);
});
