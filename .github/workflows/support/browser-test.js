const playwright = require('playwright');

async function testBrowser(browserType) {
  let launchOptions = {
    headless: true,
  };

  let contextOptions = {};

  // Browser-specific configuration for certificate handling
  if (browserType === 'firefox') {
    // Firefox user preferences for certificate handling
    launchOptions.firefoxUserPrefs = {
      'security.enterprise_roots.enabled': true,
      'security.tls.insecure_fallback_hosts': 'localhost',
      'security.cert_pinning.enforcement_level': 0,
      'security.tls.reject_SHA1_below_2016': false
    };
    // Firefox is particularly strict - use ignoreHTTPSErrors as fallback
    contextOptions.ignoreHTTPSErrors = true;
  } else if (browserType === 'chromium') {
    // Chromium-specific args for certificate handling
    launchOptions.args = ['--ignore-certificate-errors', '--ignore-ssl-errors', '--ignore-certificate-errors-spki-list'];
    // Test real cert validation with NODE_EXTRA_CA_CERTS
    contextOptions.ignoreHTTPSErrors = false;
  } else if (browserType === 'webkit') {
    // WebKit doesn't support those Chromium args - rely on NODE_EXTRA_CA_CERTS and system certs
    contextOptions.ignoreHTTPSErrors = false;
  }

  const browser = await playwright[browserType].launch(launchOptions);

  try {
    const context = await browser.newContext(contextOptions);

    const page = await context.newPage();

    // Navigate to our HTTPS site
    console.log(`Navigating to https://localhost:8443 with ${browserType}...`);
    await page.goto('https://localhost:8443', { waitUntil: 'networkidle' });

    // Check if page loaded successfully
    const title = await page.title();
    console.log('Page title:', title);

    // Check for our test content
    const content = await page.textContent('h1');
    console.log('Main heading:', content);

    if (content && content.includes('HTTPS Working')) {
      console.log('[PASS] Browser successfully loaded HTTPS page with valid certificate');

      // Get security info
      const securityState = await page.evaluate(() => {
        return {
          protocol: location.protocol,
          host: location.host,
          origin: location.origin
        };
      });

      console.log('Security info:', JSON.stringify(securityState, null, 2));
      return true;
    } else {
      console.log('[FAIL] Page content not found or incorrect');
      return false;
    }
  } catch (error) {
    console.error('[FAIL] Browser test failed:', error.message);
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
  process.exit(success ? 0 : 1);
});