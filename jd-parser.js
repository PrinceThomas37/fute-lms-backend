/**
 * Non-AI job description parser — regex + industry skill dictionaries.
 *
 * Skill extraction order:
 * 1. Requirements / qualification lines from the JD (highest priority)
 * 2. Industry dictionary (from form industry or inferred from JD text)
 * 3. Shared tools (SAP, Excel, Sage ERP, etc.)
 * 4. General professional tools
 * 5. Soft skills (communication, leadership, …) — only if nothing technical found
 */

const { SKILL_DICTIONARIES } = require('./skill-dictionaries');
const { loadLearnedSkills } = require('./learned-skills');

const MAX_SUGGESTED_SKILLS = 8;

/** Related industry clusters — scan neighbors after primary industry */
const RELATED_INDUSTRIES = {
  logistics: ['importexport', 'retail', 'manufacturing', 'automotive'],
  importexport: ['logistics', 'retail', 'manufacturing'],
  accounting: ['banking', 'mortgage', 'consulting'],
  banking: ['accounting', 'securities', 'mortgage', 'insurance'],
  healthcare: ['insurance', 'medicaldevice', 'nonprofit', 'education'],
  construction: ['realestate', 'manufacturing', 'energy'],
  technology: ['electronics', 'consulting', 'telecom', 'defense'],
  manufacturing: ['logistics', 'chemical', 'electronics', 'automotive'],
  retail: ['logistics', 'ecommerce', 'sales', 'food'],
  staffing: ['sales', 'consulting', 'technology'],
  legal: ['government', 'insurance', 'consulting'],
  hvac: ['construction', 'energy', 'manufacturing'],
  automotive: ['manufacturing', 'retail', 'logistics'],
  hospitality: ['food', 'travel', 'retail', 'entertainment'],
  education: ['nonprofit', 'healthcare', 'government'],
  sales: ['advertising', 'ecommerce', 'retail', 'consulting'],
  ecommerce: ['retail', 'advertising', 'technology', 'sales'],
  energy: ['chemical', 'construction', 'manufacturing', 'environmental'],
  biotech: ['healthcare', 'medicaldevice', 'chemical'],
  realestate: ['construction', 'banking', 'sales'],
  insurance: ['healthcare', 'banking', 'legal'],
  defense: ['technology', 'aviation', 'government', 'logistics'],
  aviation: ['logistics', 'defense', 'importexport']
};

const JD_SECTION_HEADERS = [
  'requirements?', 'qualifications?', 'skills?', 'responsibilities', 'duties',
  'what you(?:\'ll| will) need', 'what we(?:\'re| are) looking for', 'you bring',
  'must have', 'minimum qualifications?', 'preferred qualifications?',
  'nice to have', 'bonus points', 'ideal candidate', 'knowledge & experience',
  'education & experience', 'experience required', 'technical skills'
].join('|');

/** Certifications / licenses commonly seen in staffing JDs */
const CERTIFICATION_PATTERNS = [
  { label: 'CPA', re: /\b(?:CPA|C\.P\.A\.)(?:\s+certified|\s+license)?\b/i },
  { label: 'RN', re: /\b(?:RN|R\.N\.|registered nurse)\b/i },
  { label: 'LPN', re: /\b(?:LPN|L\.P\.N\.|licensed practical nurse)\b/i },
  { label: 'CNA', re: /\bCNA\b/i },
  { label: 'CDL', re: /\bCDL(?:\s+Class\s+[AB])?\b/i },
  { label: 'CDL Class A', re: /\bCDL\s+Class\s+A\b/i },
  { label: 'CDL Class B', re: /\bCDL\s+Class\s+B\b/i },
  { label: 'OSHA 10', re: /\bOSHA\s*10\b/i },
  { label: 'OSHA 30', re: /\bOSHA\s*30\b/i },
  { label: 'EPA 608', re: /\bEPA\s*608\b/i },
  { label: 'NATE', re: /\bNATE(?:\s+certified)?\b/i },
  { label: 'PMP', re: /\bPMP\b/i },
  { label: 'Six Sigma', re: /\bSix\s+Sigma(?:\s+Green\s+Belt|\s+Black\s+Belt)?\b/i },
  { label: 'AWS Certified', re: /\bAWS\s+Certified\b/i },
  { label: 'Series 7', re: /\bSeries\s+7\b/i },
  { label: 'Series 63', re: /\bSeries\s+63\b/i },
  { label: 'NMLS', re: /\bNMLS\b/i },
  { label: 'ServSafe', re: /\bServSafe\b/i },
  { label: 'HAZMAT certification', re: /\bHAZMAT(?:\s+certification|\s+certified)?\b/i },
  { label: 'forklift certification', re: /\bforklift(?:\s+certification|\s+certified)\b/i },
  { label: 'ASE certification', re: /\bASE(?:\s+certification|\s+certified)\b/i },
  { label: 'BLS', re: /\bBLS\b/i },
  { label: 'ACLS', re: /\bACLS\b/i },
  { label: 'Security clearance', re: /\b(?:active\s+)?security\s+clearance\b/i },
  { label: 'real estate license', re: /\breal\s+estate\s+license\b/i }
];

/** Known acronyms — only extract if present as whole word in JD */
const KNOWN_ACRONYMS = [
  'WMS', 'TMS', 'ERP', 'CRM', 'ATS', 'EHR', 'EMR', 'EMR', 'HRIS', 'LMS', 'POS', 'BAS', 'VFD',
  'PLC', 'CNC', 'GIS', 'DOT', 'FDA', 'EPA', 'HIPAA', 'SOX', 'AML', 'KYC', 'BSA', 'FP&A',
  'ICD-10', 'CPT', '3PL', 'LTL', 'FTL', 'MRO', 'HVAC', 'BIM', 'MEP', 'RFI', 'GMP', 'SOP', 'HR',
  'APQP', 'PPAP', 'FMEA', 'MRP', 'TPM', 'SPC', 'GD&T', 'CMMC', 'ITAR', 'FAR', 'DFARS',
  'IATA', 'CBP', 'HS', 'ERP', 'SAP', 'SQL', 'API', 'CI/CD', 'OSHA', 'EHS', 'PPE', 'SKU',
  'OTA', 'STR', 'PMS', 'F&B', 'DMS', 'F&I', 'OBD-II', 'ELISA', 'PCR', 'HPLC', 'IND', 'NDA'
];

const SOFT_SKILLS = new Set([
  'communication', 'communication skills', 'leadership', 'customer service',
  'time management', 'teamwork', 'problem solving', 'attention to detail',
  'interpersonal skills', 'organizational skills', 'multitasking', 'work ethic',
  'verbal communication', 'written communication', 'project management', 'team management'
]);

/** Cross-industry tools — matched after industry dict, before soft skills */
const SHARED_TOOLS = [
  'Microsoft Office', 'Microsoft Excel', 'Microsoft Word', 'Microsoft Outlook',
  'Excel', 'Word', 'Outlook', 'PowerPoint', 'Google Workspace', 'Google Sheets',
  'SAP', 'SAP ERP', 'Oracle', 'Oracle ERP', 'Salesforce', 'Workday', 'ServiceNow',
  'SharePoint', 'NetSuite', 'QuickBooks', 'Sage ERP', 'Sage 100', 'Sage Intacct',
  'Sage', 'Xero', 'Slack', 'Teams', 'Zoom'
];

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
  { key: 'logistics', re: /\b(logistics|warehouse|supply chain|fulfillment|WMS|TMS|forklift|CDL|3PL|distribution center|pick and pack)\b/i },
  { key: 'accounting', re: /\b(accounting|bookkeep|CPA|tax prep|audit|payroll|general ledger|accounts payable)\b/i },
  { key: 'healthcare', re: /\b(RN|LPN|nurse|clinical|patient care|hospital|EHR|Epic|Cerner|medical coding)\b/i },
  { key: 'hvac', re: /\b(HVAC|refrigeration|EPA 608|chiller|boiler|ductwork)\b/i },
  { key: 'construction', re: /\b(construction|superintendent|contractor|framing|concrete|Procore|OSHA 30)\b/i },
  { key: 'technology', re: /\b(software|developer|engineer|JavaScript|Python|React|DevOps|AWS|SQL)\b/i },
  { key: 'staffing', re: /\b(recruiting|talent acquisition|ATS|Bullhorn|staffing|sourcing candidates)\b/i },
  { key: 'banking', re: /\b(banking|loan origination|teller|core banking|commercial banking)\b/i },
  { key: 'manufacturing', re: /\b(manufacturing|production line|CNC|PLC|Six Sigma|assembly line)\b/i },
  { key: 'legal', re: /\b(paralegal|litigation|attorney|e-discovery|Westlaw|LexisNexis)\b/i },
  { key: 'retail', re: /\b(retail|store manager|merchandising|POS|cashier)\b/i },
  { key: 'importexport', re: /\b(import compliance|export compliance|customs brokerage|freight forwarding|Incoterms)\b/i },
  { key: 'automotive', re: /\b(ASE certification|dealership|OBD-II|automotive technician)\b/i },
  { key: 'education', re: /\b(curriculum development|classroom management|IEP|instructional design)\b/i },
  { key: 'insurance', re: /\b(underwriting|claims adjuster|Guidewire|actuarial)\b/i }
];

function normalizeIndustry(industry) {
  if (!industry) return null;
  const lower = String(industry).toLowerCase();
  if (/account|tax|bookkeep|cpa/.test(lower)) return 'accounting';
  if (/advertis|public relations|\bpr\b|marketing agency/.test(lower)) return 'advertising';
  if (/agricultur|farm|crop|agronomy/.test(lower)) return 'agriculture';
  if (/logistic|warehouse|fulfillment|distribution center|3pl/.test(lower)) return 'logistics';
  if (/airline|aviation|airport|aircraft|aerospace/.test(lower)) return 'aviation';
  if (/architect|construct|building material|infra|contractor/.test(lower)) return 'construction';
  if (/art|photo|journalism/.test(lower) && !/telecom/.test(lower)) return 'creative';
  if (/automotive|motor vehicle|dealership|auto repair/.test(lower)) return 'automotive';
  if (/banking|financial services/.test(lower)) return 'banking';
  if (/biotech|pharmaceutical|pharma|biopharma/.test(lower)) return 'biotech';
  if (/broadcast|media|printing/.test(lower)) return 'media';
  if (/chemical|industrial/.test(lower) && !/manufactur/.test(lower)) return 'chemical';
  if (/computer|software|hardware|tech|it\b|engineer|developer|data/.test(lower)) return 'technology';
  if (/consult/.test(lower)) return 'consulting';
  if (/consumer product|retail/.test(lower)) return 'retail';
  if (/credit|loan|mortgage|collection/.test(lower)) return 'mortgage';
  if (/defense|military|aerospace/.test(lower)) return 'defense';
  if (/education|training|library|school|universit/.test(lower)) return 'education';
  if (/electron|semiconductor/.test(lower)) return 'electronics';
  if (/employ|recruit|staffing/.test(lower)) return 'staffing';
  if (/energy|utilities|oil|petroleum|gas/.test(lower)) return 'energy';
  if (/entertain|recreation|sport|gaming/.test(lower)) return 'entertainment';
  if (/environ/.test(lower)) return 'environmental';
  if (/fashion|apparel|textile|cloth/.test(lower)) return 'fashion';
  if (/food|restaurant|culinary|beverage/.test(lower)) return 'food';
  if (/funeral|cemetery|mortuary/.test(lower)) return 'funeral';
  if (/government|civil service|public sector|federal|municipal/.test(lower)) return 'government';
  if (/health|medical|nurs|clinic|hospital|health service/.test(lower)) return 'healthcare';
  if (/homebuilding|real estate|property/.test(lower)) return 'realestate';
  if (/hotel|resort|lodging|hospitality/.test(lower)) return 'hospitality';
  if (/hvac|heating|cooling|refrigerat/.test(lower)) return 'hvac';
  if (/import|export|customs/.test(lower)) return 'importexport';
  if (/insurance|managed care/.test(lower)) return 'insurance';
  if (/internet|ecommerce|e-commerce/.test(lower)) return 'ecommerce';
  if (/landscap|horticulture|lawn/.test(lower)) return 'landscaping';
  if (/law enforcement|legal|law\b|attorney|paralegal|security service/.test(lower)) return 'legal';
  if (/manufactur|factory/.test(lower)) return 'manufacturing';
  if (/medical equipment|medical device/.test(lower)) return 'medicaldevice';
  if (/nonprofit|not for profit|social service|ngo/.test(lower)) return 'nonprofit';
  if (/office suppli|office equipment/.test(lower)) return 'officesupplies';
  if (/packag/.test(lower)) return 'packaging';
  if (/sales|marketing/.test(lower)) return 'sales';
  if (/securit(?:ies)|investment|brokerage|wealth/.test(lower)) return 'securities';
  if (/telecom|wireless|social media|telecommunicat/.test(lower)) return 'telecom';
  if (/travel|tourism/.test(lower)) return 'travel';
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
  if (t.length < 2 || t.length > 80) return '';
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

function getIndustrySkillList(industryKey) {
  if (!industryKey) return [];
  const base = SKILL_DICTIONARIES[industryKey] || [];
  const learned = loadLearnedSkills()[industryKey] || [];
  return [...base, ...learned];
}

function getRelatedIndustryKeys(industryKey) {
  if (!industryKey) return [];
  return RELATED_INDUSTRIES[industryKey] || [];
}

function extractCertifications(text) {
  const found = [];
  const seen = new Set();
  for (const { label, re } of CERTIFICATION_PATTERNS) {
    if (!re.test(text)) continue;
    const key = label.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push(label);
    }
  }
  return found;
}

function extractKnownAcronyms(text) {
  const found = [];
  const seen = new Set();
  for (const acr of KNOWN_ACRONYMS) {
    if (!skillInText(acr, text)) continue;
    const key = acr.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push(acr);
    }
  }
  return found;
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
    /(?:experience with|experience in|proficien(?:t|cy) in|knowledge of|familiarity with|skilled in|working knowledge of|hands-on with|background in|expertise in)\s+([^.,;\n]+)/gi,
    /(?:must have|required|preferred|nice to have)\s*:?\s*([^.,;\n]+)/gi
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

  const sectionHeaders = new RegExp(`(?:^|\\n)\\s*(?:${JD_SECTION_HEADERS})\\s*:?\\s*\\n([\\s\\S]*?)(?=\\n\\s*\\n|\\n\\s*[A-Z][^\\n]{0,50}:|$)`, 'gi');
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
  if (industry && getIndustrySkillList(industry).some((s) => s.toLowerCase() === lower)) score -= 35;
  if (getRelatedIndustryKeys(industry).some((rel) => getIndustrySkillList(rel).some((s) => s.toLowerCase() === lower))) score -= 20;
  if (SHARED_TOOLS.some((s) => s.toLowerCase() === lower)) score -= 20;
  if (CERTIFICATION_PATTERNS.some((c) => c.label.toLowerCase() === lower)) score -= 25;
  if (KNOWN_ACRONYMS.some((a) => a.toLowerCase() === lower)) score -= 15;
  if (skillInText(skill, text) && lower.length <= 24) score -= 5;
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

  const resolvedIndustry = normalizeIndustry(industry) || inferIndustryFromText(text) || 'general';

  for (const token of extractCommaListedSkills(text)) addSkillMatch(matches, seen, token);
  for (const token of extractInlineSkillPhrases(text)) addSkillMatch(matches, seen, token);
  for (const token of extractCertifications(text)) addSkillMatch(matches, seen, token);
  for (const token of extractKnownAcronyms(text)) addSkillMatch(matches, seen, token);

  matchSkillsFromDict(text, getIndustrySkillList(resolvedIndustry), seen, matches, 80);

  for (const relatedKey of getRelatedIndustryKeys(resolvedIndustry)) {
    matchSkillsFromDict(text, getIndustrySkillList(relatedKey), seen, matches, 80);
  }

  matchSkillsFromDict(text, SHARED_TOOLS, seen, matches, 80);

  if (resolvedIndustry !== 'general') {
    matchSkillsFromDict(text, getIndustrySkillList('general'), seen, matches, 80);
  }

  matchSkillsFromDict(text, [...SOFT_SKILLS], seen, matches, 80);

  return rankSkills(matches, resolvedIndustry, text).slice(0, MAX_SUGGESTED_SKILLS);
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
      suggested_skills: [],
      skill_1: '',
      skill_2: '',
      skill_3: '',
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
    suggested_skills: skills,
    skill_1: skills[0] || '',
    skill_2: skills[1] || '',
    skill_3: skills[2] || '',
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
  matchSkills,
  SKILL_DICTIONARIES,
  SOFT_SKILLS,
  SHARED_TOOLS,
  RELATED_INDUSTRIES,
  buildResearchFromLeadData,
  MAX_SUGGESTED_SKILLS
};
