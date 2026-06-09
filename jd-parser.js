/**
 * Non-AI job description parser — regex + industry skill dictionaries.
 *
 * Skill extraction order:
 * 1. Requirements / qualification lines from the JD (highest priority)
 * 2. Industry dictionary (from form industry or inferred from JD text)
 * 3. Shared tools (SAP, Excel, Sage ERP, etc.)
 * 4. Soft skills (communication, leadership, …) — only if nothing technical found
 */

const SOFT_SKILLS = new Set([
  'communication', 'communication skills', 'leadership', 'customer service',
  'time management', 'teamwork', 'problem solving', 'attention to detail',
  'interpersonal skills', 'organizational skills', 'multitasking', 'work ethic',
  'verbal communication', 'written communication'
]);

/** Cross-industry tools — matched after industry dict, before soft skills */
const SHARED_TOOLS = [
  'Microsoft Office', 'Microsoft Excel', 'Microsoft Word', 'Microsoft Outlook',
  'Excel', 'Word', 'Outlook', 'PowerPoint', 'Google Workspace', 'Google Sheets',
  'SAP', 'SAP ERP', 'Oracle', 'Oracle ERP', 'Salesforce', 'Workday', 'ServiceNow',
  'SharePoint', 'NetSuite', 'QuickBooks', 'Sage ERP', 'Sage 100', 'Sage Intacct',
  'Sage', 'Xero', 'Slack', 'Teams', 'Zoom'
];

const SKILL_DICTIONARIES = {
  accounting: [
    'CCH', 'CCH Axcess', 'CCH ProSystem', 'QuickBooks', 'Quickbooks', 'CPA', 'GAAP',
    'tax preparation', 'tax accounting', 'trust and estate', 'bookkeeping', 'audit',
    'Sage ERP', 'Sage 100', 'Sage Intacct', 'Sage', 'Xero', 'ProSeries', 'Lacerte',
    'UltraTax', 'payroll', 'accounts payable', 'accounts receivable', 'financial reporting',
    'general ledger', 'GL', 'month-end close', 'bank reconciliation', '1099', 'W-2',
    'Excel', 'pivot tables', 'VLOOKUP'
  ],
  hvac: [
    'EPA 608', 'EPA 609', 'NATE', 'refrigeration', 'HVAC', 'commercial HVAC',
    'residential HVAC', 'chiller', 'boiler', 'VFD', 'BAS', 'ductwork', 'sheet metal',
    'controls', 'RTU', 'split system', 'heat pump', 'refrigerant', 'combustion analysis',
    'preventive maintenance', 'Troubleshooting'
  ],
  construction: [
    'OSHA 30', 'OSHA 10', 'blueprint reading', 'estimating', 'Procore', 'PlanGrid',
    'heavy equipment', 'commercial construction', 'residential construction',
    'project superintendent', 'site superintendent', 'framing', 'concrete', 'civil',
    'sitework', 'grading', 'excavation', 'safety management', 'RFI', 'submittals',
    'AutoCAD', 'Revit', 'BIM'
  ],
  technology: [
    'JavaScript', 'TypeScript', 'Python', 'Java', 'React', 'Node.js', 'AWS', 'Azure',
    'GCP', 'SQL', 'PostgreSQL', 'MySQL', 'Kubernetes', 'Docker', 'DevOps', 'CI/CD',
    '.NET', 'C#', 'Angular', 'Vue', 'REST API', 'GraphQL', 'Linux', 'Git',
    'machine learning', 'data engineering', 'cybersecurity', 'SOC 2'
  ],
  healthcare: [
    'RN', 'LPN', 'BLS', 'ACLS', 'PALS', 'EHR', 'Epic', 'Cerner', 'Meditech',
    'med-surg', 'ICU', 'CNA', 'patient care', 'clinical', 'phlebotomy', 'HIPAA',
    'vital signs', 'EMR', 'home health', 'hospice', 'case management'
  ],
  finance: [
    'Excel', 'financial modeling', 'Bloomberg', 'CFA', 'FP&A', 'audit', 'SOX',
    'accounts payable', 'accounts receivable', 'SAP', 'Oracle', 'Hyperion',
    'variance analysis', 'budgeting', 'forecasting', 'P&L', 'balance sheet',
    'treasury', 'credit analysis', 'KYC', 'AML'
  ],
  manufacturing: [
    'lean manufacturing', 'Six Sigma', '5S', 'Kaizen', 'CNC', 'PLC', 'ISO 9001',
    'quality control', 'production', 'assembly', 'maintenance', 'TPM', 'GMP',
    'SPC', 'root cause analysis', 'preventive maintenance', 'blueprint reading',
    'welding', 'machining', 'injection molding'
  ],
  logistics: [
    'CDL', 'CDL Class A', 'CDL Class B', 'forklift', 'forklift certification',
    'reach truck', 'cherry picker', 'order picker', 'WMS', 'warehouse management system',
    'TMS', 'transportation management', 'supply chain', 'inventory management',
    'order fulfillment', 'shipping', 'receiving', 'pick and pack', 'dispatch',
    'DOT', 'HAZMAT', 'HAZMAT certification', 'warehouse operations', '3PL',
    'cross-docking', 'RF scanner', 'barcode scanning', 'load planning',
    'route planning', 'last mile', 'freight', 'LTL', 'FTL', 'drayage',
    'SAP TM', 'Manhattan', 'Blue Yonder', 'logistics coordination'
  ],
  legal: [
    'litigation', 'corporate law', 'contracts', 'paralegal', 'e-discovery',
    'compliance', 'legal research', 'Westlaw', 'LexisNexis', 'case management',
    'discovery', 'brief writing', 'contract review', 'NDA', 'MSA'
  ],
  retail: [
    'POS', 'point of sale', 'inventory', 'merchandising', 'store management',
    'loss prevention', 'visual merchandising', 'planogram', 'cash handling',
    'inventory control', 'shrink reduction', 'retail operations'
  ],
  /** Fallback when industry unknown — professional tools only, NOT soft skills */
  general: [
    'Microsoft Office', 'Excel', 'Word', 'Outlook', 'PowerPoint', 'Google Workspace',
    'data entry', 'typing', 'reporting', 'scheduling', 'documentation'
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

const INDUSTRY_INFERENCE_RULES = [
  { key: 'logistics', re: /\b(logistics|warehouse|supply chain|fulfillment|dispatch|freight|WMS|TMS|forklift|CDL|3PL|distribution center)\b/i },
  { key: 'accounting', re: /\b(accounting|bookkeep|CPA|tax prep|audit|payroll|GL|general ledger|accounts payable)\b/i },
  { key: 'hvac', re: /\b(HVAC|refrigeration|EPA 608|chiller|boiler|ductwork)\b/i },
  { key: 'construction', re: /\b(construction|superintendent|contractor|framing|concrete|Procore|OSHA 30)\b/i },
  { key: 'technology', re: /\b(software|developer|engineer|JavaScript|Python|React|DevOps|AWS|SQL)\b/i },
  { key: 'healthcare', re: /\b(RN|LPN|nurse|clinical|patient care|hospital|EHR|Epic|Cerner)\b/i },
  { key: 'finance', re: /\b(financial modeling|FP&A|investment banking|treasury|Bloomberg|CFA)\b/i },
  { key: 'manufacturing', re: /\b(manufacturing|production line|CNC|PLC|Six Sigma|assembly line)\b/i },
  { key: 'legal', re: /\b(paralegal|litigation|attorney|e-discovery|Westlaw|LexisNexis)\b/i },
  { key: 'retail', re: /\b(retail|store manager|merchandising|POS|cashier)\b/i }
];

function normalizeIndustry(industry) {
  if (!industry) return null;
  const lower = String(industry).toLowerCase();
  if (/account|tax|bookkeep|cpa|audit/.test(lower)) return 'accounting';
  if (/hvac|heating|cooling|refrigerat/.test(lower)) return 'hvac';
  if (/construct|infra|build|contractor/.test(lower)) return 'construction';
  if (/tech|software|it\b|engineer|developer|data/.test(lower)) return 'technology';
  if (/health|medical|nurs|clinic|hospital/.test(lower)) return 'healthcare';
  if (/financ|bank|capital|invest/.test(lower)) return 'finance';
  if (/manufact|production|factory/.test(lower)) return 'manufacturing';
  if (/logistic|transport|warehouse|supply|distribution/.test(lower)) return 'logistics';
  if (/legal|law\b|attorney|paralegal/.test(lower)) return 'legal';
  if (/retail|store|merchand/.test(lower)) return 'retail';
  return null;
}

function inferIndustryFromText(text) {
  for (const rule of INDUSTRY_INFERENCE_RULES) {
    if (rule.re.test(text)) return rule.key;
  }
  return null;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function skillInText(skill, text) {
  const pattern = new RegExp(`\\b${escapeRegex(skill)}\\b`, 'i');
  return pattern.test(text);
}

function isSoftSkill(skill) {
  const lower = String(skill).toLowerCase().trim();
  if (SOFT_SKILLS.has(lower)) return true;
  return /^(strong|excellent|good)\s+(communication|leadership|customer service)/i.test(lower)
    || /\b(communication|leadership|customer service|time management)\s+skills?\b/i.test(lower);
}

function cleanSkillPhrase(raw) {
  let t = String(raw || '').trim();
  if (!t) return '';
  t = t.replace(/^[\s\-•*]+/, '').replace(/[.)]+$/, '').trim();
  t = t.replace(/^(?:strong|excellent|good|solid|proven|effective)\s+/i, '');
  t = t.replace(/^(?:must have|required|preferred|minimum|ideal)\s*:?\s*/i, '');
  t = t.replace(/\b(?:experience with|experience in|proficien(?:t|cy) in|knowledge of|familiarity with|ability to|understanding of)\s+/gi, '');
  t = t.replace(/\b(?:required|preferred|is a plus|a plus|plus|desired|nice to have)\b/gi, '').trim();
  t = t.replace(/\s{2,}/g, ' ').trim();
  if (t.length < 2 || t.length > 60) return '';
  if (/^(the|a|an|or|and|with|in|for|to|years?|year|experience)$/i.test(t)) return '';
  if (/^\d+\+?\s*years?/i.test(t)) return '';
  return t;
}

function addSkillMatch(matches, seen, skill) {
  const cleaned = cleanSkillPhrase(skill);
  if (!cleaned) return;
  const norm = cleaned.toLowerCase();
  if (seen.has(norm)) return;
  seen.add(norm);
  matches.push(cleaned);
}

function matchSkillsFromDict(text, dict, seen, matches, limit) {
  const sorted = [...dict].sort((a, b) => b.length - a.length);
  for (const skill of sorted) {
    if (matches.length >= limit) break;
    if (!skillInText(skill, text)) continue;
    addSkillMatch(matches, seen, skill);
  }
}

function extractInlineSkillPhrases(text) {
  const found = [];
  const seen = new Set();
  const patterns = [
    /(?:experience with|experience in|proficien(?:t|cy) in|knowledge of|familiarity with|skilled in)\s+([^.,;\n]+)/gi,
    /(?:must have|required|preferred)\s*:?\s*([^.,;\n]+)/gi
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(text)) !== null) {
      const chunk = m[1].replace(/\band\b/gi, ',');
      chunk.split(/[,;|•]/).forEach((part) => {
        const token = cleanSkillPhrase(part);
        if (!token) return;
        const key = token.toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          found.push(token);
        }
      });
    }
  }
  return found;
}

function extractCommaListedSkills(text) {
  const found = [];
  const seen = new Set();

  const sectionHeaders = /(?:^|\n)\s*(?:requirements?|qualifications?|skills?|what you(?:'ll| will) need|must have|minimum qualifications?|preferred qualifications?)\s*:?\s*\n([\s\S]*?)(?=\n\s*\n|\n\s*[A-Z][^\n]{0,40}:|$)/gi;
  let m;
  while ((m = sectionHeaders.exec(text)) !== null) {
    const block = m[1];
    block.split(/\n/).forEach((line) => {
      const bullet = line.replace(/^\s*[-•*]\s+/, '').trim();
      const token = cleanSkillPhrase(bullet.replace(/\band\b/gi, ','));
      if (!token) return;
      token.split(/[,;|•]/).forEach((part) => {
        const p = cleanSkillPhrase(part);
        if (!p) return;
        const key = p.toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          found.push(p);
        }
      });
    });
  }

  const inlineRe = /(?:requirements?|qualifications?|skills?|must have|experience (?:with|in)|proficien(?:t|cy) in|knowledge of)[:\s-]*([^\n]+)/gi;
  while ((m = inlineRe.exec(text)) !== null) {
    const chunk = m[1].replace(/\band\b/gi, ',');
    chunk.split(/[,;|•]/).forEach((part) => {
      const token = cleanSkillPhrase(part);
      if (!token) return;
      const key = token.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        found.push(token);
      }
    });
  }

  const bulletRe = /(?:^|\n)\s*[-•*]\s+([^\n]+)/g;
  while ((m = bulletRe.exec(text)) !== null) {
    const token = cleanSkillPhrase(m[1]);
    if (!token) continue;
    if (/^(requirements?|qualifications?|responsibilities|duties|about the role|job description)\b/i.test(token)) continue;
    const key = token.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push(token);
    }
  }

  return found;
}

function skillScore(skill, industry, text) {
  let score = 0;
  const lower = skill.toLowerCase();
  if (isSoftSkill(skill)) score += 100;
  if (industry && SKILL_DICTIONARIES[industry]) {
    const inDict = SKILL_DICTIONARIES[industry].some((s) => s.toLowerCase() === lower || skillInText(s, skill) || skillInText(skill, s));
    if (inDict) score -= 30;
  }
  if (SHARED_TOOLS.some((s) => s.toLowerCase() === lower)) score -= 20;
  if (skillInText(skill, text) && lower.length <= 20) score -= 5;
  return score;
}

function rankSkills(matches, industry, text) {
  return [...matches].sort((a, b) => {
    const scoreDiff = skillScore(a, industry, text) - skillScore(b, industry, text);
    if (scoreDiff !== 0) return scoreDiff;
    return a.length - b.length;
  });
}

function matchSkills(text, industry) {
  const seen = new Set();
  const matches = [];
  const limit = 3;

  const resolvedIndustry = normalizeIndustry(industry) || inferIndustryFromText(text);

  for (const token of extractCommaListedSkills(text)) {
    addSkillMatch(matches, seen, token);
  }

  for (const token of extractInlineSkillPhrases(text)) {
    addSkillMatch(matches, seen, token);
  }

  if (resolvedIndustry && SKILL_DICTIONARIES[resolvedIndustry]) {
    matchSkillsFromDict(text, SKILL_DICTIONARIES[resolvedIndustry], seen, matches, 50);
  }

  matchSkillsFromDict(text, SHARED_TOOLS, seen, matches, 50);

  if (resolvedIndustry !== 'general') {
    matchSkillsFromDict(text, SKILL_DICTIONARIES.general, seen, matches, 50);
  }

  matchSkillsFromDict(text, [...SOFT_SKILLS], seen, matches, 50);

  return rankSkills(matches, resolvedIndustry, text).slice(0, limit);
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
  if (/\b25\s*%\s*travel\b/i.test(text)) return '25%';
  if (/\b(travel required|must travel|willing to travel|extensive travel)\b/i.test(text)) return 'required';
  const pct = text.match(/(\d{1,3})\s*%\s*travel/i);
  if (pct && pct[1] === '25') return '25%';
  if (pct) return 'required';
  return '';
}

function detectSalaryPeriod(text) {
  if (/\b(per\s*hour|\/\s*hr|hourly)\b/i.test(text)) return 'hour';
  if (/\b(per\s*week|weekly|\/\s*wk)\b/i.test(text)) return 'week';
  return 'year';
}

function parseSalaryBounds(salaryDisplay, period = 'year') {
  const nums = String(salaryDisplay || '').replace(/,/g, '').match(/\d+/g);
  if (!nums || !nums.length) return { salary_min: null, salary_max: null };
  let values = nums.map(Number);
  if (period === 'year' && values.every(v => v < 1000)) values = values.map(v => v * 1000);
  const min = Math.min(...values);
  const max = Math.max(...values);
  return { salary_min: min, salary_max: max };
}

function extractLocalRequirement(text) {
  if (/\b(must be local|local candidates only|local to|on-?site|in-?office|no remote)\b/i.test(text)) return true;
  if (/\b(remote|work from home|hybrid|nationwide)\b/i.test(text)) return false;
  return null;
}

function parseJobDescription(text, industry) {
  const jd = String(text || '').trim();
  if (!jd) {
    return {
      skills: [],
      skill_1: '',
      skill_2: '',
      salary_display: '',
      salary_range: '',
      salary_min: null,
      salary_max: null,
      salary_period: 'year',
      location: '',
      city: '',
      local_hint: '',
      travel: '',
      local_required: null
    };
  }

  const skills = matchSkills(jd, industry);
  const salary = extractSalary(jd);
  const salaryPeriod = detectSalaryPeriod(jd);
  const salaryBounds = parseSalaryBounds(salary.salary_display, salaryPeriod);
  const loc = extractLocation(jd);
  const travel = extractTravel(jd);
  const localRequired = extractLocalRequirement(jd);

  return {
    skills,
    skill_1: skills[0] || '',
    skill_2: skills[1] || '',
    salary_display: salary.salary_display,
    salary_range: salary.salary_range,
    salary_min: salaryBounds.salary_min,
    salary_max: salaryBounds.salary_max,
    salary_period: salaryPeriod,
    location: loc.location,
    city: loc.city,
    local_hint: localRequired === true ? (loc.local_hint || loc.city) : (loc.local_hint || ''),
    travel,
    local_required: localRequired
  };
}

function buildResearchFromLeadData({ notes, jdText, position, location, salaryRange, industry }) {
  const parts = [];
  if (position) parts.push(`Title: ${position}`);
  if (notes) parts.push(String(notes).trim());
  if (jdText) parts.push(String(jdText).trim());
  const jd_raw = parts.filter(Boolean).join('\n\n').trim();
  const seedText = jd_raw || [position, location, salaryRange].filter(Boolean).join(' ');
  if (!seedText.trim()) return null;

  const parsed = parseJobDescription(seedText, industry);
  if (salaryRange) {
    parsed.salary_display = parsed.salary_display || String(salaryRange).trim();
    parsed.salary_range = parsed.salary_range || String(salaryRange).trim();
  }
  if (location) {
    const loc = String(location).trim();
    if (!parsed.location) {
      parsed.location = loc;
      parsed.city = loc.includes(',') ? loc.split(',')[0].trim() : loc;
    }
    if (!parsed.local_hint && parsed.city) parsed.local_hint = parsed.city;
  }

  return {
    requirements: parsed,
    jd_raw: jd_raw || null,
    parsed_at: new Date().toISOString(),
    source: 'import'
  };
}

module.exports = {
  parseJobDescription,
  normalizeIndustry,
  inferIndustryFromText,
  SKILL_DICTIONARIES,
  SOFT_SKILLS,
  SHARED_TOOLS,
  buildResearchFromLeadData
};
