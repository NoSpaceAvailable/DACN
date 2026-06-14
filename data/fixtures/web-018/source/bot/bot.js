// Admin bot: visits a user-submitted URL with the flag in a fragment.
const puppeteer = require('puppeteer');

async function visit(url) {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox']
  });
  const page = await browser.newPage();
  // The flag is part of the URL fragment when the bot lands on the note page.
  await page.goto(url, { waitUntil: 'networkidle0', timeout: 10000 });
  await new Promise(r => setTimeout(r, 5000));
  await browser.close();
}

module.exports = { visit };
