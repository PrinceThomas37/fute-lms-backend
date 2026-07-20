// Verifies the new role-relevant recruiter dashboard: a recruiter sees
// recruiting widgets (pipeline, interviews, subs) and none of the BD lead-gen
// widgets (Your Team, Response rate trend, Industry breakdown), and the nav
// hides Leads but keeps My Jobs near the top.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright-core';

const PUBLIC_DIR = path.resolve('/home/user/fute-lms-backend/public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const fp = path.join(PUBLIC_DIR, p);
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404); return res.end('nf'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
    res.end(data);
  });
});
const PORT = await new Promise(r => server.listen(0, '127.0.0.1', () => r(server.address().port)));
const BASE = `http://127.0.0.1:${PORT}`;

const results = [];
const step = (name, ok, detail='') => { results.push({name, ok}); console.log((ok?'[PASS] ':'[FAIL] ')+name+(detail?' — '+detail:'')); };
const pageErrors = [];

function findChromium() {
  if (process.env.PLAYWRIGHT_CHROMIUM) return process.env.PLAYWRIGHT_CHROMIUM;
  const base = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (base && fs.existsSync(path.join(base, 'chromium'))) return path.join(base, 'chromium');
  return 'chromium';
}

let browser;
try {
  browser = await chromium.launch({ executablePath: findChromium(), headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] });
  const context = await browser.newContext();
  await context.route('**', r => r.request().url().startsWith(BASE) ? r.continue() : r.abort());
  const page = await context.newPage();
  page.on('pageerror', e => pageErrors.push(String(e)));

  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('button:has-text("Continue as Guest")', { timeout: 15000 });
  await page.click('button:has-text("Continue as Guest")');
  await page.waitForSelector('#sidebar', { timeout: 15000 });

  // Morph the guest into a pure recruiter with a stubbed /recruiting-dashboard payload
  await page.evaluate(() => {
    STATE.user.role = 'recruiter';
    STATE.user.roles = ['recruiter'];
    STATE.user.name = 'James Wilson';
    STATE._recDash = {
      _at: Date.now(), role: 'recruiter',
      jobs: { total: 2, active: 2 },
      by_stage: { 'Sourced': 3, 'Screening': 1, 'Submitted to BDM': 0, 'Submitted to Client': 2,
        'Interview Scheduled': 1, 'Interview Completed': 0, 'Offer': 1, 'Confirmation': 0,
        'Placement': 1, 'Rejected': 1, 'Not Joined': 0, 'On Hold': 0 },
      submissions_week: 7, submissions_month: 7,
      jobs_assigned: { week: 1, month: 2, quarter: 2, total: 2 },
      top_jobs: [
        { id: 'j1', job_code: 'JO-101', job_title: 'Senior Java Developer', client: 'Acme Corp', city: 'Austin', state: 'TX',
          status: 'Active', priority: 'High', team_subs: 9, team_subs_14d: 5, my_subs: 3, created_at: new Date().toISOString() },
        { id: 'j2', job_code: 'JO-102', job_title: 'Data Engineer', client: 'Globex', city: 'Remote', state: '',
          status: 'Active', priority: 'Normal', team_subs: 4, team_subs_14d: 2, my_subs: 1, created_at: new Date().toISOString() }
      ],
      upcoming_interviews: [{ candidate: 'Jane Doe', interview_at: new Date(Date.now()+86400000).toISOString(), interview_location: 'Zoom' }],
      awaiting_approval: 0
    };
    STATE.page = 'dashboard';
    render();
  });
  await page.waitForTimeout(300);

  const content = await page.evaluate(() => document.getElementById('content').innerHTML);
  const sidebar = await page.evaluate(() => document.getElementById('sidebar').innerText);

  // Recruiting widgets present
  step('Banner shows recruiting stats', content.includes('Subs this week') && content.includes('Subs this month'));
  step('Tiles: My Jobs / Offers / Placements', content.includes('My Jobs') && content.includes('Offers') && content.includes('Placements'));
  step('Candidate pipeline card renders stages', content.includes('My candidate pipeline') && content.includes('Sourced') && content.includes('Interview Scheduled'));
  step('Upcoming interviews shows candidate', content.includes('Upcoming interviews') && content.includes('Jane Doe') && content.includes('Zoom'));
  step('Reminders widget present', content.includes('Reminders'));

  // My jobs card
  step('Jobs-assigned timeline stats', content.includes('Assigned this week') && content.includes('This quarter') && content.includes('All time'));
  step('Top active jobs listed with details', content.includes('Senior Java Developer') && content.includes('JO-101') && content.includes('Acme Corp'));
  step('Top jobs show team + my activity', content.includes('team · 14d') && content.includes('my subs'));
  step('Priority badge on hot job', content.includes('High'));
  step('All my jobs button present', content.includes('All my jobs'));
  const jobClick = await page.evaluate(() => {
    const el = Array.from(document.querySelectorAll('#content [onclick]'))
      .find(e => (e.getAttribute('onclick')||'').includes("bdOpenSubmissions('j1')"));
    return !!el;
  });
  step('Top job row clicks through to submissions', jobClick);

  // BD lead-gen widgets gone
  step('No "Your Team" leads table', !content.includes('Your Team'));
  step('No "Response rate trend"', !content.includes('Response rate trend'));
  step('No "Industry breakdown"', !content.includes('Industry breakdown'));
  step('No lead-stage "Pipeline overview"', !content.includes('Pipeline overview'));
  step('No lead banner stats', !content.includes('Leads this period') && !content.includes('Emails sent'));

  // Nav relevance
  const navItems = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.sb-nav .nav-item')).map(e => e.textContent.trim()));
  step('Nav hides Leads', !navItems.includes('Leads'), navItems.join(' | '));
  step('Nav keeps My Jobs after Dashboard', navItems[0] === 'Dashboard' && navItems[1] === 'My Jobs', navItems.join(' | '));
  step('Nav keeps Candidates & Sourcing', navItems.includes('Candidates') && navItems.includes('Sourcing'));

  // Sanity: BD guest still gets the classic dashboard
  await page.evaluate(() => {
    STATE.user.role = 'bd'; STATE.user.roles = ['bd'];
    document.querySelectorAll('[data-bdnav],[data-atsnav],[data-srcnav]').forEach(e => e.remove());
    render();
  });
  await page.waitForTimeout(200);
  const bdContent = await page.evaluate(() => document.getElementById('content').innerHTML);
  const bdNav = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.sb-nav .nav-item')).map(e => e.textContent.trim()));
  step('BD still sees lead widgets', bdContent.includes('Response rate trend') && bdContent.includes('Industry breakdown'));
  step('BD still sees Leads nav', bdNav.includes('Leads'), bdNav.join(' | '));

  step('No JS page errors', pageErrors.length === 0, pageErrors.join('; ').slice(0, 300));
} finally {
  if (browser) await browser.close();
  server.close();
}
const fails = results.filter(r => !r.ok).length;
console.log(`\nSUMMARY: ${results.length - fails}/${results.length} passed`);
process.exit(fails ? 1 : 0);
