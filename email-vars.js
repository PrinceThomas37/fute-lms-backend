/**
 * Shared email template variables and Daniel-style default templates.
 */

const DEFAULT_TEMPLATES = {
  o1_subject: 'Assistance for {{pos}} in {{loc}}',
  o1_body: `Hi {{fn}},

I'm reaching out about your {{pos}} opening in {{loc}}.
I have a few qualified profiles{{skills_line}} — I'd like to check before sending anything over.

Are you still open to reviewing external candidates?
There's no charge to review resumes; we only charge if you hire.

Thanks & Regards,
{{sender}}`,
  fu1_subject: 'Re: Assistance for {{pos}} in {{loc}}',
  fu1_body: `Hi {{fn}},

Just checking in on my note about your {{pos}} opening in {{loc}}.
I still have a few relevant profiles{{skills_line}} if you're reviewing candidates.

No pressure — just let me know if you'd like to see any.

Thanks,
{{sender}}`,
  fu2_subject: 'Re: Assistance for {{pos}} in {{loc}}',
  fu2_body: `Hi {{fn}},

Last quick note on the {{pos}} role in {{loc}}.
Happy to send profiles when timing works — no charge to review.

Thanks,
{{sender}}`
};

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
  const skills = Array.isArray(req.skills) ? req.skills : [];
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
    skill_1: skills[0] || '',
    skill_2: skills[1] || '',
    skill_3: skills[2] || '',
    skills_line: formatSkillsLine(skills),
    salary_range: salaryDisplay,
    salary_line: salaryLine,
    local_line: localLine,
    city
  };
}

module.exports = {
  DEFAULT_TEMPLATES,
  buildEmailVars,
  fillTemplate,
  formatSkillsLine
};
