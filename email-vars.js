/**
 * Shared email template variables and outreach style variants (O1 + FU1 + FU2).
 */

const DEFAULT_TEMPLATES = {
  o1_subject: '{{pos}} — 2 profiles',
  o1_body: `Hi {{fn}},

Saw the {{pos}} posting in {{loc}}. Two screened candidates on my desk have done {{job_resp}} on {{company_service}} work — both open to direct hire, neither submitted to you yet.

Want the resumes? If the role is already filled, tell me and I'll close this out.`,
  fu1_subject: 'Re: {{pos}} — 2 profiles',
  fu1_body: `Hi {{fn}},

Floating this back up — both candidates are still available for the {{pos}} role. A one-word reply works: 'send' or 'pass'.`,
  fu2_subject: 'Re: {{pos}} — 2 profiles',
  fu2_body: `Hi {{fn}},

Closing this out for now. If {{pos}} reopens or you'd like the profiles later, just reply to this thread anytime.`
};

/**
 * Twenty matched outreach styles — each with O1, FU1, and FU2.
 * Keep in sync with OUTREACH_STYLE_PRESETS in public/app.js.
 */
const OUTREACH_VARIANTS = [
  {
    id: 'v1',
    label: 'Two profiles',
    o1: {
      subject: '{{pos}} — 2 profiles',
      body: `Hi {{fn}},

Saw the {{pos}} posting in {{loc}}. Two screened candidates on my desk have done {{job_resp}} on {{company_service}} work — both open to direct hire, neither submitted to you yet.

Want the resumes? If the role is already filled, tell me and I'll close this out.`
    },
    fu1: {
      subject: 'Re: {{pos}} — 2 profiles',
      body: `Hi {{fn}},

Floating this back up — both candidates are still available for the {{pos}} role. A one-word reply works: 'send' or 'pass'.`
    },
    fu2: {
      subject: 'Re: {{pos}} — 2 profiles',
      body: `Hi {{fn}},

Closing this out for now. If {{pos}} reopens or you'd like the profiles later, just reply to this thread anytime.`
    }
  },
  {
    id: 'v2',
    label: 'Still open?',
    o1: {
      subject: '{{pos}} — still open?',
      body: `Hi {{fn}},

Is the {{pos}} role in {{loc}} still open? Before I send anything over, I'd rather check — I have a shortlist with {{job_resp}} experience from {{company_service}} work that reads like a match, but only if you're still looking.

Happy to share or stand down, whichever helps.`
    },
    fu1: {
      subject: 'Re: {{pos}} — still open?',
      body: `Hi {{fn}},

Checking once more on the {{pos}} role — still hiring? If yes, the shortlist is ready to send.`
    },
    fu2: {
      subject: 'Re: {{pos}} — still open?',
      body: `Hi {{fn}},

I'll assume the timing is off and step back. If the search picks up again, this thread will reach me.`
    }
  },
  {
    id: 'v3',
    label: 'Hard to fill',
    o1: {
      subject: 'the {{pos}} search',
      body: `Hi {{fn}},

Roles like your {{pos}} opening in {{loc}} tend to sit longer than they should — the {{job_resp}} requirement narrows the pool fast. We happen to have a few people from {{company_service}} backgrounds who clear that bar and are open to direct hire.

Worth a look at their resumes?`
    },
    fu1: {
      subject: 'Re: the {{pos}} search',
      body: `Hi {{fn}},

Following up on the {{pos}} search — the candidates I mentioned are still available if the seat is still open.`
    },
    fu2: {
      subject: 'Re: the {{pos}} search',
      body: `Hi {{fn}},

Last note from me. If the {{pos}} role is still proving hard to fill, the resumes are yours for the asking — anytime.`
    }
  },
  {
    id: 'v4',
    label: 'Ultra short',
    o1: {
      subject: '{{pos}} ({{loc}})',
      body: `Hi {{fn}},

Short version: screened candidates with {{job_resp}} experience, open to direct hire, ready for your {{pos}} role in {{loc}}.

Send the resumes over?`
    },
    fu1: {
      subject: 'Re: {{pos}} ({{loc}})',
      body: `Hi {{fn}},

Still have them if you want them — {{pos}}, {{loc}}. Yes or no works.`
    },
    fu2: {
      subject: 'Re: {{pos}} ({{loc}})',
      body: `Hi {{fn}},

Closing the loop on this one. Reply anytime if you'd like the resumes down the road.`
    }
  },
  {
    id: 'v5',
    label: 'Right person?',
    o1: {
      subject: '{{pos}} — right person to ask?',
      body: `Hi {{fn}},

Are you the right person for the {{pos}} hiring in {{loc}}? I have a few screened, direct-hire candidates with {{job_resp}} experience from {{company_service}} work, and I'd rather send them to whoever owns the search.

If that's you, happy to share. If not, could you point me the right way?`
    },
    fu1: {
      subject: 'Re: {{pos}} — right person to ask?',
      body: `Hi {{fn}},

Circling back — should the {{pos}} resumes come to you, or someone else on the team?`
    },
    fu2: {
      subject: 'Re: {{pos}} — right person to ask?',
      body: `Hi {{fn}},

I'll stop here. If the {{pos}} search lands on your desk later, just reply to this thread.`
    }
  },
  {
    id: 'v6',
    label: 'JD anchored',
    o1: {
      subject: 'your {{pos}} requirements',
      body: `Hi {{fn}},

I read the {{pos}} description closely — the {{job_resp}} piece is the part most applicants miss. The candidates I'd send have actually done that work in {{company_service}} settings, which is why I'm writing instead of just pushing them through a portal.

Open to seeing two or three resumes?`
    },
    fu1: {
      subject: 'Re: your {{pos}} requirements',
      body: `Hi {{fn}},

Following up — those {{job_resp}} profiles for the {{pos}} role are still with me. Want them?`
    },
    fu2: {
      subject: 'Re: your {{pos}} requirements',
      body: `Hi {{fn}},

I'll leave this here. If the {{pos}} search is still live and you'd like the resumes, one reply is all it takes.`
    }
  },
  {
    id: 'v7',
    label: 'Screen done',
    o1: {
      subject: '{{pos}} — first screen done',
      body: `Hi {{fn}},

The first-round screen is usually the slow part of a {{pos}} search. Ours is done: a few candidates with {{job_resp}} experience on {{company_service}} work, already vetted, open to direct hire in {{loc}}.

Want to skip straight to reviewing resumes?`
    },
    fu1: {
      subject: 'Re: {{pos}} — first screen done',
      body: `Hi {{fn}},

Quick follow-up — the pre-screened {{pos}} candidates are still available if useful.`
    },
    fu2: {
      subject: 'Re: {{pos}} — first screen done',
      body: `Hi {{fn}},

Final nudge from me. The screened profiles stay available — reply whenever the {{pos}} search needs them.`
    }
  },
  {
    id: 'v8',
    label: 'One candidate',
    o1: {
      subject: 'one person for {{pos}}',
      body: `Hi {{fn}},

One candidate specifically made me write: strong {{job_resp}} background from {{company_service}} work, open to direct hire, and a clean match for your {{pos}} role in {{loc}}. There are a couple of others too, but this one is worth your two minutes.

Shall I send the resume?`
    },
    fu1: {
      subject: 'Re: one person for {{pos}}',
      body: `Hi {{fn}},

That candidate for the {{pos}} role is still available — want the resume?`
    },
    fu2: {
      subject: 'Re: one person for {{pos}}',
      body: `Hi {{fn}},

I'll close this out, but if you'd like that {{pos}} resume at any point, it's one reply away.`
    }
  },
  {
    id: 'v9',
    label: 'No strings',
    o1: {
      subject: 'resumes for {{pos}} — no strings',
      body: `Hi {{fn}},

Simple offer on the {{pos}} role in {{loc}}: I send a few screened resumes with {{job_resp}} experience, you look them over, and a one-word 'pass' ends it if they don't fit. No pitch attached.

Want them?`
    },
    fu1: {
      subject: 'Re: resumes for {{pos}} — no strings',
      body: `Hi {{fn}},

Same offer as before on {{pos}} — resumes to review, nothing owed. Interested?`
    },
    fu2: {
      subject: 'Re: resumes for {{pos}} — no strings',
      body: `Hi {{fn}},

Standing down on this one. The offer holds if the {{pos}} role ever needs it — just reply.`
    }
  },
  {
    id: 'v10',
    label: 'Open a while',
    o1: {
      subject: 'how long has {{pos}} been open?',
      body: `Hi {{fn}},

If the {{pos}} role in {{loc}} has been open more than a few weeks, it's usually the {{job_resp}} requirement doing the filtering. That's the exact profile we screen for on {{company_service}} work — and a few of those people are available for direct hire now.

Want the resumes while the search is still warm?`
    },
    fu1: {
      subject: 'Re: how long has {{pos}} been open?',
      body: `Hi {{fn}},

Still holding those {{pos}} profiles — say the word and they're in your inbox.`
    },
    fu2: {
      subject: 'Re: how long has {{pos}} been open?',
      body: `Hi {{fn}},

Closing this thread on my end. If {{pos}} is still unfilled next month, reply and I'll send what's current.`
    }
  },
  {
    id: 'v11',
    label: 'Your process',
    o1: {
      subject: '{{pos}} — quick logistics question',
      body: `Hi {{fn}},

Before sending anything on the {{pos}} role in {{loc}}: how do you prefer outside resumes — straight to you, or through a portal or process? I have screened, direct-hire candidates with {{job_resp}} experience and I'd rather follow your process than clutter your inbox.

Point me the right way?`
    },
    fu1: {
      subject: 'Re: {{pos}} — quick logistics question',
      body: `Hi {{fn}},

Following up — happy to route the {{pos}} resumes however works best for you. Direct, or via your process?`
    },
    fu2: {
      subject: 'Re: {{pos}} — quick logistics question',
      body: `Hi {{fn}},

I'll leave it with you. Whenever you want the {{pos}} profiles, reply here and I'll send them however you prefer.`
    }
  },
  {
    id: 'v12',
    label: 'Reply 1-2-3',
    o1: {
      subject: '{{pos}} — three ways to reply',
      body: `Hi {{fn}},

A short stack of screened resumes is ready for your {{pos}} role in {{loc}} — {{job_resp}} experience, {{company_service}} backgrounds, open to direct hire.

Reply '1' and I'll send them, '2' if I should check back later, '3' if the role is filled and I'll close this out.`
    },
    fu1: {
      subject: 'Re: {{pos}} — three ways to reply',
      body: `Hi {{fn}},

Same three options on the {{pos}} resumes — 1 send now, 2 later, 3 close out. One character does it.`
    },
    fu2: {
      subject: 'Re: {{pos}} — three ways to reply',
      body: `Hi {{fn}},

No number needed — I'll close this out myself. The resumes stay available if {{pos}} ever calls for them.`
    }
  },
  {
    id: 'v13',
    label: 'Candid',
    o1: {
      subject: 'honest note on {{pos}}',
      body: `Hi {{fn}},

Candidly: this is a recruiter email, and you likely get plenty. The only reason this one is worth your ten seconds is that the candidates behind it have real {{job_resp}} experience from {{company_service}} work and are open to direct hire for your {{pos}} role in {{loc}}.

If that's useful, say 'send'. If not, 'pass' and I'm gone.`
    },
    fu1: {
      subject: 'Re: honest note on {{pos}}',
      body: `Hi {{fn}},

Same honest note, shorter: {{pos}} resumes, ready. Send or pass?`
    },
    fu2: {
      subject: 'Re: honest note on {{pos}}',
      body: `Hi {{fn}},

Pass it is — closing out. If the {{pos}} search changes, this thread still works.`
    }
  },
  {
    id: 'v14',
    label: 'Benchmark',
    o1: {
      subject: 'benchmark for your {{pos}} pipeline',
      body: `Hi {{fn}},

Even if your {{pos}} pipeline in {{loc}} is healthy, a couple of outside resumes make a useful benchmark — you'll know in two minutes whether your internal candidates stack up. Mine have {{job_resp}} experience from {{company_service}} work and are open to direct hire.

Want them as a measuring stick?`
    },
    fu1: {
      subject: 'Re: benchmark for your {{pos}} pipeline',
      body: `Hi {{fn}},

Offer stands — a couple of {{pos}} resumes as a benchmark, no obligation past a glance.`
    },
    fu2: {
      subject: 'Re: benchmark for your {{pos}} pipeline',
      body: `Hi {{fn}},

Closing this out. If you ever want an outside read on the {{pos}} pool, reply here.`
    }
  },
  {
    id: 'v15',
    label: 'Save a week',
    o1: {
      subject: '{{pos}} — save a sourcing week',
      body: `Hi {{fn}},

Sourcing for {{job_resp}} skills usually eats a week or two before the first decent resume shows up. Skip that part: I have screened candidates from {{company_service}} backgrounds ready for your {{pos}} role in {{loc}}, open to direct hire.

Shall I send them today?`
    },
    fu1: {
      subject: 'Re: {{pos}} — save a sourcing week',
      body: `Hi {{fn}},

The {{pos}} resumes are still ready to go same-day — want them?`
    },
    fu2: {
      subject: 'Re: {{pos}} — save a sourcing week',
      body: `Hi {{fn}},

Wrapping this thread. Whenever the {{pos}} search needs a shortcut, one reply brings the resumes.`
    }
  },
  {
    id: 'v16',
    label: 'Yes or no',
    o1: {
      subject: 'resumes — {{pos}}',
      body: `Hi {{fn}},

No preamble: {{pos}} role, {{loc}}, candidates with {{job_resp}} experience from {{company_service}} work, screened, open to direct hire.

Do you want the resumes — yes or no?`
    },
    fu1: {
      subject: 'Re: resumes — {{pos}}',
      body: `Hi {{fn}},

Same question, still standing: {{pos}} resumes — yes or no?`
    },
    fu2: {
      subject: 'Re: resumes — {{pos}}',
      body: `Hi {{fn}},

Taking that as a no and closing out. A future 'yes' in this thread will still find me.`
    }
  },
  {
    id: 'v17',
    label: 'Shortlist timing',
    o1: {
      subject: 'before you shortlist for {{pos}}',
      body: `Hi {{fn}},

If you're mid-shortlist on the {{pos}} role in {{loc}}, this is the useful moment for outside profiles — after offer stage it's too late. The ones I have bring {{job_resp}} experience from {{company_service}} work and are open to direct hire.

Want them in the mix before you narrow down?`
    },
    fu1: {
      subject: 'Re: before you shortlist for {{pos}}',
      body: `Hi {{fn}},

Still time to add the {{pos}} profiles to your shortlist? They're ready when you are.`
    },
    fu2: {
      subject: 'Re: before you shortlist for {{pos}}',
      body: `Hi {{fn}},

I'll bow out of this round. If the {{pos}} shortlist reopens, reply and they're yours.`
    }
  },
  {
    id: 'v18',
    label: 'Minimal',
    o1: {
      subject: '{{pos}}, {{loc}}',
      body: `Hi {{fn}},

A few screened people worth your time for the {{pos}} role: {{job_resp}} experience, {{company_service}} backgrounds, open to direct hire in {{loc}}.

Resumes on request.`
    },
    fu1: {
      subject: 'Re: {{pos}}, {{loc}}',
      body: `Hi {{fn}},

They're still available. Resumes on request, as before.`
    },
    fu2: {
      subject: 'Re: {{pos}}, {{loc}}',
      body: `Hi {{fn}},

Last line from me: the offer stays open in this thread whenever you want it.`
    }
  },
  {
    id: 'v19',
    label: 'Off your plate',
    o1: {
      subject: 'extra hands on {{pos}}?',
      body: `Hi {{fn}},

Filling a {{pos}} seat in {{loc}} usually lands on top of someone's actual job. If sourcing help is welcome, I have screened candidates with {{job_resp}} experience from {{company_service}} work, open to direct hire, ready whenever you are.

Want me to take that piece off your plate?`
    },
    fu1: {
      subject: 'Re: extra hands on {{pos}}?',
      body: `Hi {{fn}},

Offer is still open — happy to carry the sourcing piece on {{pos}} if useful.`
    },
    fu2: {
      subject: 'Re: extra hands on {{pos}}?',
      body: `Hi {{fn}},

Stepping back for now. If the {{pos}} load gets heavy later, this thread is the shortcut.`
    }
  },
  {
    id: 'v20',
    label: 'Correct me',
    o1: {
      subject: 'am I off base on {{pos}}?',
      body: `Hi {{fn}},

Reading your {{pos}} posting in {{loc}}, I matched it to candidates with {{job_resp}} experience from {{company_service}} work — but you know the role better than the JD does. If I'm off base, one line on what actually matters would sharpen who I send.

And if I'm on target: want the resumes?`
    },
    fu1: {
      subject: 'Re: am I off base on {{pos}}?',
      body: `Hi {{fn}},

Still glad to be corrected — or to send the {{pos}} resumes as matched. Either reply helps.`
    },
    fu2: {
      subject: 'Re: am I off base on {{pos}}?',
      body: `Hi {{fn}},

I'll close this out without the answer. If the {{pos}} search evolves, tell me what changed and I'll re-match.`
    }
  }
];

/** @deprecated Use OUTREACH_VARIANTS — kept for callers expecting flat subject/body */
const OUTREACH_O1_VARIANTS = OUTREACH_VARIANTS.map(v => ({
  id: v.id,
  label: v.label,
  subject: v.o1.subject,
  body: v.o1.body
}));

function getVariantById(id) {
  const key = String(id || '').trim();
  return OUTREACH_VARIANTS.find(v => v.id === key) || OUTREACH_VARIANTS[0];
}

function shuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** Deal full style variants from a shuffled deck — each used once before any repeat. */
function buildRotatingTemplateDeck(count, variants = OUTREACH_VARIANTS) {
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

const SENDER_JOB_TITLE = 'Recruitment Manager';

function normalizeSenderTitle(text) {
  return String(text || '')
    .replace(/BD Manager at Fute Global LLC/gi, `${SENDER_JOB_TITLE} at Fute Global LLC`)
    .replace(/BD Manager \|/gi, `${SENDER_JOB_TITLE} |`);
}

function fillTemplate(tmpl, vars) {
  const filled = (tmpl || '').replace(/{{(\w+)}}/g, (m, k) => (vars[k] !== undefined && vars[k] !== null ? vars[k] : m));
  return normalizeSenderTitle(filled);
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
  /Hope you had a great break/i,
  // Retired outreach copy (announced "cold email" / over-templated) — refresh to current defaults
  /yet to be introduced/i,
  /we haven't met yet/i,
  /We've not been introduced/i,
  /Pleasure to connect, albeit virtually/i
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
  return normalizeSenderTitle(val);
}

module.exports = {
  DEFAULT_TEMPLATES,
  OUTREACH_VARIANTS,
  OUTREACH_O1_VARIANTS,
  getVariantById,
  buildEmailVars,
  fillTemplate,
  formatSkillsLine,
  formatJobResp,
  formatCompanyService,
  isLegacyTemplate,
  resolveTemplate,
  normalizeSenderTitle,
  SENDER_JOB_TITLE,
  buildRotatingTemplateDeck,
  isRandomTemplateMode
};
