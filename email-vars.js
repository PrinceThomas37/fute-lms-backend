/**
 * Shared email template variables and Daniel-style default templates.
 */

const DEFAULT_TEMPLATES = {
  o1_subject: 'Assistance for {{pos}} in {{loc}}',
  o1_body: `Hi {{fn}},

We are yet to be introduced, but I am {{sender}}, Recruitment Manager at Fute Global LLC.

I came across your job opening for a {{pos}} in {{loc}}. I have gone through the job description, and we have several candidates who are experienced in {{job_resp}} for {{company_service}} projects. They are a good fit for the position. These candidates are open to direct hire and yet to be screened for your current open position.

Would you like to review the resumes?

I look forward to hearing from you.`,
  fu1_subject: 'Re: Assistance for {{pos}} in {{loc}}',
  fu1_body: `Hi {{fn}},

Just following up on my note about your {{pos}} opening in {{loc}}. I still have candidates experienced in {{job_resp}} for {{company_service}} projects who may be a good fit.

Would you still like to review their resumes?

I look forward to hearing from you.`,
  fu2_subject: 'Re: Assistance for {{pos}} in {{loc}}',
  fu2_body: `Hi {{fn}},

Last quick note on the {{pos}} role in {{loc}}. I still have screened-ready candidates with {{job_resp}} experience on {{company_service}} projects whenever timing works for you.

Would you like me to share a few resumes?

I look forward to hearing from you.`
};

/** Four outreach-1 variants — must stay in sync with OUTREACH_STYLE_PRESETS in public/index.html */
const OUTREACH_O1_VARIANTS = [
  {
    id: 'v1',
    label: 'Introduction',
    subject: 'Assistance for {{pos}} in {{loc}}',
    body: `Hi {{fn}},

We are yet to be introduced, but I am {{sender}}, Recruitment Manager at Fute Global LLC.

I came across your job opening for a {{pos}} in {{loc}}. I have gone through the job description, and we have several candidates who are experienced in {{job_resp}} for {{company_service}} projects. They are a good fit for the position. These candidates are open to direct hire and yet to be screened for your current open position.

Would you like to review the resumes?

I look forward to hearing from you.`
  },
  {
    id: 'v2',
    label: 'Warm opener',
    subject: 'Candidates for your {{pos}} opening in {{loc}}',
    body: `Hi {{fn}},

I hope this note finds you well. I'm {{sender}}, Recruitment Manager at Fute Global LLC — we haven't met yet.

I noticed your {{pos}} opening in {{loc}} and reviewed the job description. We have several candidates with strong experience in {{job_resp}}, particularly on {{company_service}} projects. They appear well aligned with what you're looking for and are available for direct hire, pending your screening.

Would you be open to reviewing their resumes?

I look forward to hearing from you.`
  },
  {
    id: 'v3',
    label: 'Respectful reach-out',
    subject: '{{pos}} role in {{loc}} — resume review',
    body: `Hi {{fn}},

My name is {{sender}}, Recruitment Manager at Fute Global LLC. We've not been introduced, but I wanted to reach out respectfully.

Your {{pos}} role in {{loc}} caught my attention. After reading through the requirements, I have a shortlist of candidates experienced in {{job_resp}} across {{company_service}} projects — a solid match for the position. They're open to direct hire and have not yet been presented to you.

Would you like me to share their resumes for review?

I look forward to hearing from you.`
  },
  {
    id: 'v4',
    label: 'Concise intro',
    subject: 'Quick introduction — {{pos}} in {{loc}}',
    body: `Hi {{fn}},

I'm {{sender}}, Recruitment Manager at Fute Global LLC. Pleasure to connect, albeit virtually.

I came across the {{pos}} opening in {{loc}} and went through the job description. We have candidates with hands-on {{job_resp}} experience on {{company_service}} engagements who look like a strong fit. They're direct-hire ready and haven't been screened for your role yet.

If helpful, would you like to review a few resumes?

I look forward to hearing from you.`
  }
];

function shuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** Deal templates from a shuffled deck — each variant used once before any repeat. */
function buildRotatingTemplateDeck(count, variants = OUTREACH_O1_VARIANTS) {
  const deck = [];
  while (deck.length < count) {
    deck.push(...shuffleInPlace([...variants]));
  }
  return deck.slice(0, count);
}

function isRandomTemplateMode(value) {
  return value === 'true' || value === true;
}

function formatJobResp(skills) {
  const list = (skills || []).filter(Boolean).slice(0, 3);
  if (!list.length) return 'the key requirements';
  if (list.length === 1) return list[0];
  if (list.length === 2) return `${list[0]} and ${list[1]}`;
  return `${list.slice(0, -1).join(', ')}, and ${list[list.length - 1]}`;
}

function formatCompanyService(industry) {
  const val = String(industry || '').trim();
  return val || 'relevant';
}

function formatSkillsLine(skills) {
  const list = (skills || []).filter(Boolean).slice(0, 3);
  if (!list.length) return '';
  if (list.length === 1) return ` with experience in ${list[0]}`;
  if (list.length === 2) return ` with experience in ${list[0]} and ${list[1]}`;
  return ` with experience in ${list.slice(0, -1).join(', ')}, and ${list[list.length - 1]}`;
}

function fillTemplate(tmpl, vars) {
  return (tmpl || '').replace(/{{(\w+)}}/g, (m, k) => (vars[k] !== undefined && vars[k] !== null ? vars[k] : m));
}

/**
 * Build merge variables from job, contact, and sender display name.
 */
function buildEmailVars({ job, contact, senderDisplayName }) {
  const research = job?.research || {};
  const req = research.requirements || {};
  const skills = Array.isArray(req.skills) ? [...req.skills] : [];
  if (req.skill_1) skills[0] = req.skill_1;
  if (req.skill_2) skills[1] = req.skill_2;
  const filteredSkills = skills.filter(Boolean).slice(0, 3);
  const companyExpertise = research.company?.expertise || '';
  const loc = job?.location || job?.company?.location || req.location || '';
  const city = req.city || (loc.includes(',') ? loc.split(',')[0].trim() : loc);
  const salaryDisplay = req.salary_display || job?.salary_range || '';
  const localHint = req.local_hint || '';

  let localLine = '';
  if (localHint) localLine = ` Must be local to ${localHint}.`;
  else if (req.local_required === true && city) localLine = ` Local to ${city} preferred.`;

  const salaryLine = salaryDisplay ? ` (${salaryDisplay})` : '';

  return {
    fn: contact?.first_name || '',
    ln: contact?.last_name || '',
    company: job?.company?.name || '',
    pos: job?.position || '',
    ind: job?.company?.industry || job?.industry || '',
    loc,
    desig: contact?.designation || 'Hiring Manager',
    sender: senderDisplayName || '',
    skill_1: filteredSkills[0] || '',
    skill_2: filteredSkills[1] || '',
    skill_3: filteredSkills[2] || '',
    skills_line: formatSkillsLine(filteredSkills),
    job_resp: formatJobResp(filteredSkills),
    company_service: formatCompanyService(companyExpertise || job?.company?.industry || job?.industry || ''),
    salary_range: salaryDisplay,
    salary_line: salaryLine,
    local_line: localLine,
    city
  };
}

/** Fingerprints of outdated outreach templates saved in app_settings. */
const LEGACY_TEMPLATE_MARKERS = [
  /BD Manager at Fute Global LLC/i,
  /BD Manager \|/i,
  /I'd like to check before sending/i,
  /I'm reaching out about your {{pos}} opening/i,
  /There's no charge to review resumes/i,
  /At Fute Global/i,
  /specializ(e|ing) in connecting/i,
  /15-?\s*minute call/i,
  /Opportunity regarding/i,
  /Hope you had a great break/i
];

function isLegacyTemplate(text) {
  const val = String(text || '').trim();
  if (!val) return false;
  return LEGACY_TEMPLATE_MARKERS.some(re => re.test(val));
}

/** Return saved template or Daniel default when empty / legacy. */
function resolveTemplate(saved, templateKey) {
  const val = String(saved || '').trim();
  if (!val || isLegacyTemplate(val)) return DEFAULT_TEMPLATES[templateKey] || '';
  return val;
}

module.exports = {
  DEFAULT_TEMPLATES,
  OUTREACH_O1_VARIANTS,
  buildEmailVars,
  fillTemplate,
  formatSkillsLine,
  formatJobResp,
  formatCompanyService,
  isLegacyTemplate,
  resolveTemplate,
  buildRotatingTemplateDeck,
  isRandomTemplateMode
};
