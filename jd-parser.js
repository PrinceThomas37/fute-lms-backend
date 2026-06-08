/**
 * Non-AI job description parser — regex + industry skill dictionaries.
 */

const SKILL_DICTIONARIES = {
  accounting: [
    'CCH', 'QuickBooks', 'Quickbooks', 'CPA', 'GAAP', 'tax preparation', 'trust and estate',
    'bookkeeping', 'audit', 'Sage', 'Xero', 'ProSeries', 'Lacerte', 'UltraTax', 'payroll',
    'accounts payable', 'accounts receivable', 'financial reporting', 'Excel'
  ],
  hvac: [
    'EPA 608', 'NATE', 'refrigeration', 'HVAC', 'commercial HVAC', 'residential HVAC',
    'chiller', 'boiler', 'VFD', 'BAS', 'ductwork', 'sheet metal', 'controls'
  ],
  construction: [
    'OSHA 30', 'OSHA 10', 'blueprint reading', 'estimating', 'Procore', 'heavy equipment',
    'commercial construction', 'residential construction', 'project superintendent',
    'site superintendent', 'framing', 'concrete', 'civil'
  ],
  technology: [
    'JavaScript', 'Python', 'Java', 'React', 'Node.js', 'AWS', 'Azure', 'SQL', 'Kubernetes',
    'Docker', 'TypeScript', '.NET', 'C#', 'Angular', 'Vue', 'DevOps', 'CI/CD'
  ],
  healthcare: [
    'RN', 'LPN', 'BLS', 'ACLS', 'EHR', 'Epic', 'Cerner', 'med-surg', 'ICU', 'CNA',
    'patient care', 'clinical', 'phlebotomy'
  ],
  finance: [
    'Excel', 'financial modeling', 'Bloomberg', 'CFA', 'FP&A', 'audit', 'SOX',
    'accounts payable', 'accounts receivable', 'SAP', 'Oracle'
  ],
  manufacturing: [
    'lean manufacturing', 'Six Sigma', 'CNC', 'PLC', 'ISO 9001', 'quality control',
    'production', 'assembly', 'maintenance'
  ],
  logistics: [
    'CDL', 'forklift', 'WMS', 'supply chain', 'DOT', 'HAZMAT', 'warehouse', 'dispatch'
  ],
  legal: [
    'litigation', 'corporate law', 'contracts', 'paralegal', 'e-discovery', 'compliance'
  ],
  retail: [
    'POS', 'inventory', 'merchandising', 'customer service', 'store management'
  ],
  general: [
    'Microsoft Office', 'communication', 'leadership', 'project management',
    'customer service', 'Excel', 'time management'
  ]
};

const US_STATES = {
  AL: 'Alabama', AK: 'Alaska', AZ: 'Arizona', AR: 'Arkansas', CA: 'California',
  CO: 'Colorado', CT: 'Connecticut', DE: 'Delaware', FL: 'Florida', GA: 'Georgia',
  HI: 'Hawaii', ID: 'Idaho', IL: 'Illinois', IN: 'Indiana', IA: 'Iowa', KS: 'Kansas',
  KY: 'Kentucky', LA: 'Louisiana', ME: 'Maine', MD: 'Maryland', MA: 'Massachusetts',
  MI: 'Michigan', MN: 'Minnesota', MS: 'Mississippi', MO: 'Missouri', MT: 'Montana',
  NE: 'Nebraska', NV: 'Nevada', NH: 'New Hampshire', NJ: 'New Jersey', NM: 'New Mexico',
  NY: 'New York', NC: 'North Carolina', ND: 'North Dakota', OH: 'Ohio', OK: 'Oklahoma',
  OR: 'Oregon', PA: 'Pennsylvania', RI: 'Rhode Island', SC: 'South Carolina',
  SD: 'South Dakota', TN: 'Tennessee', TX: 'Texas', UT: 'Utah', VT: 'Vermont',
  VA: 'Virginia', WA: 'Washington', WV: 'West Virginia', WI: 'Wisconsin', WY: 'Wyoming',
  DC: 'District of Columbia'
};

function normalizeIndustry(industry) {
  if (!industry) return 'general';
  const lower = String(industry).toLowerCase();
  if (/account|tax|bookkeep|cpa|audit/.test(lower)) return 'accounting';
  if (/hvac|heating|cooling|refrigerat/.test(lower)) return 'hvac';
  if (/construct|infra|build|contractor/.test(lower)) return 'construction';
  if (/tech|software|it\b|engineer|developer|data/.test(lower)) return 'technology';
  if (/health|medical|nurs|clinic|hospital/.test(lower)) return 'healthcare';
  if (/financ|bank|capital|invest/.test(lower)) return 'finance';
  if (/manufact|production|factory/.test(lower)) return 'manufacturing';
  if (/logistic|transport|warehouse|supply/.test(lower)) return 'logistics';
  if (/legal|law\b|attorney|paralegal/.test(lower)) return 'legal';
  if (/retail|store|merchand/.test(lower)) return 'retail';
  return 'general';
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function addSkillMatch(matches, seen, skill, text, lower) {
  const norm = skill.toLowerCase();
  if (seen.has(norm)) return;
  const pattern = new RegExp(`\\b${escapeRegex(skill)}\\b`, 'i');
  if (pattern.test(text) || lower.includes(norm)) {
    seen.add(norm);
    matches.push(skill);
  }
}

function matchSkillsFromDict(text, lower, dict, seen, matches, limit) {
  for (const skill of dict) {
    if (matches.length >= limit) break;
    addSkillMatch(matches, seen, skill, text, lower);
  }
}

function extractCommaListedSkills(text) {
  const found = [];
  const seen = new Set();
  const sectionRe = /(?:requirements?|qualifications?|skills?|must have|experience (?:with|in)|proficien(?:t|cy) in|knowledge of)[:\s-]*([^\n]+)/gi;
  let m;
  while ((m = sectionRe.exec(text)) !== null) {
    const chunk = m[1].replace(/\band\b/gi, ',');
    chunk.split(/[,;|•]/).forEach((part) => {
      const token = part.replace(/^[\s\-•*]+/, '').replace(/[.)]+$/, '').trim();
      if (!token || token.length < 2 || token.length > 50) return;
      if (/^(the|a|an|or|and|with|in|for|to|years?|experience)$/i.test(token)) return;
      const key = token.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        found.push(token);
      }
    });
  }
  const bulletRe = /(?:^|\n)\s*[-•*]\s+([^\n]+)/g;
  while ((m = bulletRe.exec(text)) !== null) {
    const line = m[1].trim();
    if (line.length < 3 || line.length > 80) continue;
    if (/^(requirements?|qualifications?|responsibilities|duties)\b/i.test(line)) continue;
    const key = line.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push(line.length > 40 ? line.slice(0, 40).trim() : line);
    }
  }
  return found;
}

function matchSkills(text, industry) {
  const seen = new Set();
  const matches = [];
  const lower = text.toLowerCase();
  const key = normalizeIndustry(industry);

  const primaryDict = [
    ...(SKILL_DICTIONARIES[key] || []),
    ...(key !== 'general' ? SKILL_DICTIONARIES.general : [])
  ];
  matchSkillsFromDict(text, lower, primaryDict, seen, matches, 3);

  if (matches.length < 3) {
    for (const dictKey of Object.keys(SKILL_DICTIONARIES)) {
      if (dictKey === key) continue;
      matchSkillsFromDict(text, lower, SKILL_DICTIONARIES[dictKey], seen, matches, 3);
      if (matches.length >= 3) break;
    }
  }

  if (matches.length < 3) {
    for (const token of extractCommaListedSkills(text)) {
      if (matches.length >= 3) break;
      const norm = token.toLowerCase();
      if (!seen.has(norm)) {
        seen.add(norm);
        matches.push(token);
      }
    }
  }

  return matches.slice(0, 3);
}

function extractSalary(text) {
  const kRange = text.match(/\$\s?(\d{2,3})\s?[kK]\s*(?:[-–—to]+\s*\$?\s?(\d{2,3})\s?[kK])/);
  if (kRange) {
    const display = `$${kRange[1]}K-$${kRange[2]}K`;
    return { salary_display: display, salary_range: display };
  }
  const kSingle = text.match(/\$\s?(\d{2,3})\s?[kK]\b/);
  if (kSingle) {
    const display = `$${kSingle[1]}K`;
    return { salary_display: display, salary_range: display };
  }
  const dollarRange = text.match(/\$\s?([\d,]+)\s*(?:[-–—to]+\s*\$?\s?([\d,]+))/);
  if (dollarRange) {
    const low = parseInt(dollarRange[1].replace(/,/g, ''), 10);
    const high = parseInt(dollarRange[2].replace(/,/g, ''), 10);
    if (!Number.isNaN(low) && !Number.isNaN(high)) {
      const fmt = (n) => (n >= 1000 ? `$${Math.round(n / 1000)}K` : `$${n}`);
      const display = `${fmt(low)}-${fmt(high)}`;
      return { salary_display: display, salary_range: display };
    }
  }
  const labeled = text.match(/(?:salary|compensation|pay)\s*:?\s*\$?\s?([\d,]+(?:\s?[kK])?)\s*(?:[-–—to]+\s*\$?\s?([\d,]+(?:\s?[kK])?))?/i);
  if (labeled) {
    const fmtPart = (v) => {
      const clean = v.replace(/,/g, '').trim();
      if (/k$/i.test(clean)) return `$${clean.replace(/k/i, '')}K`;
      const n = parseInt(clean, 10);
      return Number.isNaN(n) ? `$${clean}` : (n >= 1000 ? `$${Math.round(n / 1000)}K` : `$${n}`);
    };
    const display = labeled[2] ? `${fmtPart(labeled[1])}-${fmtPart(labeled[2])}` : fmtPart(labeled[1]);
    return { salary_display: display, salary_range: display };
  }
  return { salary_display: '', salary_range: '' };
}

function extractLocation(text) {
  const cityState = text.match(/\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)*),\s*([A-Z]{2})\b/);
  if (cityState) {
    return {
      location: `${cityState[1]}, ${cityState[2]}`,
      city: cityState[1],
      local_hint: cityState[1]
    };
  }
  const locatedIn = text.match(/(?:located in|based in|office in|position in)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)/i);
  if (locatedIn) {
    return { location: locatedIn[1], city: locatedIn[1], local_hint: locatedIn[1] };
  }
  for (const [abbr, name] of Object.entries(US_STATES)) {
    const re = new RegExp(`\\b([A-Z][a-z]+(?:\\s[A-Z][a-z]+)*)[,\\s]+${name}\\b`, 'i');
    const m = text.match(re);
    if (m) return { location: `${m[1]}, ${abbr}`, city: m[1], local_hint: m[1] };
  }
  return { location: '', city: '', local_hint: '' };
}

function extractTravel(text) {
  if (/\b(no travel|minimal travel|0% travel)\b/i.test(text)) return 'none';
  const pct = text.match(/(\d{1,3})\s*%\s*travel/i);
  if (pct) return `${pct[1]}%`;
  if (/\b(travel required|must travel|willing to travel|extensive travel)\b/i.test(text)) return 'required';
  return '';
}

function extractLocalRequirement(text) {
  if (/\b(must be local|local candidates only|local to|on-?site|in-?office|no remote)\b/i.test(text)) return true;
  if (/\b(remote|work from home|hybrid|nationwide)\b/i.test(text)) return false;
  return null;
}

/**
 * Parse pasted job description text.
 * @param {string} text - Raw JD text
 * @param {string} [industry] - Job/company industry for skill matching
 * @returns {object} Parsed fields for jobs.research.requirements
 */
function parseJobDescription(text, industry) {
  const jd = String(text || '').trim();
  if (!jd) {
    return {
      skills: [],
      salary_display: '',
      salary_range: '',
      location: '',
      city: '',
      local_hint: '',
      travel: '',
      local_required: null
    };
  }

  const skills = matchSkills(jd, industry);
  const salary = extractSalary(jd);
  const loc = extractLocation(jd);
  const travel = extractTravel(jd);
  const localRequired = extractLocalRequirement(jd);

  return {
    skills,
    salary_display: salary.salary_display,
    salary_range: salary.salary_range,
    location: loc.location,
    city: loc.city,
    local_hint: localRequired === true ? (loc.local_hint || loc.city) : (loc.local_hint || ''),
    travel,
    local_required: localRequired
  };
}

module.exports = { parseJobDescription, normalizeIndustry, SKILL_DICTIONARIES };
