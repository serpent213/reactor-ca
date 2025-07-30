const playwright = require('playwright');

async function testBrowser(browserType) {
  const browser = await playwright[browserType].launch({
    headless: true,
    args: ['--ignore-certificate-errors', '--ignore-ssl-errors', '--ignore-certificate-errors-spki-list']
  });

  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: false  // We want to test real cert validation
    });

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