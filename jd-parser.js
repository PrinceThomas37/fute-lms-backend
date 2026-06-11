/**
 * Non-AI job description parser — regex + structure-aware extraction.
 *
 * Skill extraction order (highest → lowest priority):
 * 1. "N years of X" phrases — the single strongest JD signal
 * 2. Parenthetical skill lists  e.g. "Java (Spring, Hibernate)"
 * 3. Bullet lines from Required / Qualifications sections
 * 4. Bullet lines from Preferred / Nice-to-have sections
 * 5. Inline "experience with / proficiency in" phrases
 * 6. Industry dictionary terms present in the JD text
 * 7. Shared tools (SAP, Excel, Salesforce …)
 * 8. Soft skills — only if nothing technical was found
 *
 * Education lines, degree requirements, and benefit descriptions are
 * explicitly filtered out so they do not appear as skill suggestions.
 */

const { SKILL_DICTIONARIES } = require('./skill-dictionaries');
const { loadLearnedSkills } = require('./learned-skills');

const MAX_SUGGESTED_SKILLS = 8;

// ─────────────────────────────────────────────────────────────────
// Section tier definitions
// Sections are split from the JD text and given a priority tier.
// Tier 1 = Required, Tier 2 = Preferred, Tier 3 = Responsibilities,
// Tier 4 = ignore (About, Benefits, Equal-opportunity boilerplate)
// ─────────────────────────────────────────────────────────────────
const SECTION_TIERS = {
  required: [
    'requirements?', 'qualifications?', 'must.have', 'minimum qualifications?',
    'required qualifications?', 'technical skills?', 'experience required',
    'knowledge & experience', 'education & experience',
    'what you(?:\'ll| will) (need|bring)', 'you bring',
    'what we(?:\'re| are) looking for', 'ideal candidate',
    'who you are', 'about you'
  ],
  preferred: [
    'preferred qualifications?', 'nice.to.have', 'bonus points', 'a.plus',
    'preferred skills?', 'desired qualifications?', 'would be great',
    'great to have', 'additionally'
  ],
  responsibilities: [
    'responsibilities', 'duties', 'what you(?:\'ll| will) do',
    'your role', 'the role', 'day.to.day', 'in this role', 'job duties',
    'key responsibilities', 'primary responsibilities', 'about the role'
  ],
  ignore: [
    'benefit', 'perks?', 'about (?:us|the company|our company)',
    'why (?:join|work|us)', 'our culture', 'equal opportunity',
    'who we are', 'compensation', 'what we offer', 'we offer',
    'our team', 'our mission'
  ]
};

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

// ─────────────────────────────────────────────────────────────────
// NEW: Filter out education / degree requirements before they
// become skill suggestions. These are never real job skills.
// ─────────────────────────────────────────────────────────────────
function isEducationPhrase(skill) {
  const s = String(skill || '').trim();
  return /^(?:bachelor|master|associate|high school|phd|ph\.d|doctorate|mba|j\.d\.|juris|m\.s\.|b\.s\.|b\.a\.|degree|diploma|ged|certificate)/i.test(s)
    || /\b(?:bachelor'?s?|master'?s?|associate'?s?)\s+(?:degree|of)/i.test(s)
    || /\b(?:degree|diploma)\s+(?:in|required|preferred)/i.test(s)
    || /^(?:college|university|academic)\s/i.test(s);
}

// ─────────────────────────────────────────────────────────────────
// NEW: Filter out generic "ability to / willingness to" sentences
// that are duties, not skills.
// ─────────────────────────────────────────────────────────────────
function isGenericAbilityPhrase(skill) {
  return /^(?:ability|willingness|capacity|desire)\s+to\b/i.test(skill)
    || /^(?:must be able|should be able)\b/i.test(skill)
    || /^(?:work in|work with|work on)\s+a\b/i.test(skill)
    || skill.split(/\s+/).length > 6; // anything >6 words is almost certainly a sentence fragment
}

function cleanSkillPhrase(raw) {
  let t = String(raw || '').trim();
  if (!t) return '';
  t = t.replace(/^[\s\-•*]+/, '').replace(/[.)]+$/, '').trim();
  // Strip trailing unclosed parenthetical (comma-splits can leave "Excel (pivot tables")
  t = t.replace(/\s*\([^)]*$/, '').trim();
  t = t.replace(/^(?:strong|excellent|good|solid|proven|effective)\s+/i, '');
  t = t.replace(/^(?:must have|required|preferred|minimum|ideal)\s*:?\s*/i, '');
  t = t.replace(/\b(?:experience with|experience in|proficien(?:t|cy) in|knowledge of|familiarity with|ability to|understanding of)\s+/gi, '');
  t = t.replace(/\b(?:required|preferred|is a plus|a plus|plus|desired|nice to have)\b/gi, '').trim();
  // Strip trailing generic nouns that add no meaning to a skill name
  t = t.replace(/\s+(?:experience|skills?|background|knowledge|proficiency|expertise)$/i, '').trim();
  t = t.replace(/\s{2,}/g, ' ').trim();
  if (t.length < 2 || t.length > 60) return ''; // tightened from 80 to 60
  if (/^(the|a|an|or|and|with|in|for|to|years?|year|experience)$/i.test(t)) return '';
  t = t.replace(/^\d+\+?\s*(?:to\s*\d+\+?)?\s*years?\s+(?:of\s+)?/i, '').trim();
  if (!t || /^(experience|of)$/i.test(t)) return '';
  if (isEducationPhrase(t) || isGenericAbilityPhrase(t)) return '';
  return t;
}

function addSkillMatch(matches, seen, skill, tier) {
  const cleaned = cleanSkillPhrase(skill);
  if (!cleaned) return;
  const norm = cleaned.toLowerCase();
  if (seen.has(norm)) return;
  seen.add(norm);
  matches.push({ skill: cleaned, tier: tier || 99 });
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

function matchSkillsFromDict(text, dict, seen, matches, limit, tier) {
  const sorted = [...dict].sort((a, b) => b.length - a.length);
  for (const skill of sorted) {
    if (matches.length >= limit) break;
    if (!skillInText(skill, text)) continue;
    addSkillMatch(matches, seen, skill, tier);
  }
}

// ─────────────────────────────────────────────────────────────────
// NEW: Extract "N+ years of X" as the strongest required-skill signal.
// "5+ years of React", "3 years experience in SQL Server" etc.
// ─────────────────────────────────────────────────────────────────
function extractYearsOfExperience(text) {
  const found = [];
  const seen = new Set();
  // Require an explicit "of / with / in / using / experience" bridge word so we don't
  // accidentally grab verb phrases like "4+ years managing operations".
  const re = /\b\d+[ \t]*(?:\+|[ \t]*to[ \t]*\d+)?[ \t]*years?[ \t]+(?:of[ \t]+experience[ \t]+(?:with|in|using)[ \t]+|experience[ \t]+(?:with|in|using)[ \t]+|of[ \t]+)([A-Za-z][A-Za-z0-9 \t\.\-\/\+#]{1,40})/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const raw = m[1].trim();
    // Skip if the phrase starts with a gerund (verb-ing) — it's a duty, not a skill
    if (/^[A-Z]?[a-z]+ing\b/.test(raw)) continue;
    // Trim trailing noise words
    const trimmed = raw.replace(/\s+(?:experience|preferred|required|a plus|plus|desired|or more|minimum).*$/i, '').trim();
    const cleaned = cleanSkillPhrase(trimmed);
    if (!cleaned) continue;
    const key = cleaned.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push(cleaned);
    }
  }
  return found;
}

// ─────────────────────────────────────────────────────────────────
// NEW: Extract parenthetical skill lists.
// "experience with Java (Spring Boot, Maven, Hibernate)" →
// ["Spring Boot", "Maven", "Hibernate"]
// ─────────────────────────────────────────────────────────────────
function extractParentheticalSkillLists(text) {
  const found = [];
  const seen = new Set();
  const re = /\(([^)]{4,120})\)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const inner = m[1];
    // Only treat as a skill list if it contains commas or slashes (i.e. multiple items)
    if (!(/[,\/]/.test(inner))) continue;
    inner.split(/[,\/]/).forEach((part) => {
      const cleaned = cleanSkillPhrase(part.trim());
      if (!cleaned) return;
      if (cleaned.split(/\s+/).length > 4) return; // skip sentence fragments
      const key = cleaned.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        found.push(cleaned);
      }
    });
  }
  return found;
}

// ─────────────────────────────────────────────────────────────────
// NEW: Split JD into named sections with priority tiers.
// Returns { required: string, preferred: string, responsibilities: string, body: string }
// ─────────────────────────────────────────────────────────────────
function splitIntoSections(text) {
  const sections = { required: '', preferred: '', responsibilities: '', body: text };

  function buildPattern(labels) {
    return new RegExp(
      `(?:^|\\n)\\s*(?:${labels.join('|')})\\s*:?\\s*(?:\\n|$)([\\s\\S]*?)(?=(?:\\n\\s*(?:${
        [...SECTION_TIERS.required, ...SECTION_TIERS.preferred,
          ...SECTION_TIERS.responsibilities, ...SECTION_TIERS.ignore].join('|')
      })\\s*:?\\s*(?:\\n|$))|$)`,
      'gi'
    );
  }

  // Walk through the text line by line, labelling each block
  const lines = text.split('\n');
  let currentTier = 'body';
  const blocks = { required: [], preferred: [], responsibilities: [], body: [], ignore: [] };

  const tierPatterns = {};
  for (const [tier, labels] of Object.entries(SECTION_TIERS)) {
    tierPatterns[tier] = new RegExp(`^\\s*(?:${labels.join('|')})\\s*:?\\s*$`, 'i');
  }

  for (const line of lines) {
    let matched = false;
    for (const [tier, re] of Object.entries(tierPatterns)) {
      if (re.test(line)) {
        currentTier = tier;
        matched = true;
        break;
      }
    }
    if (!matched) blocks[currentTier].push(line);
  }

  sections.required = blocks.required.join('\n');
  sections.preferred = blocks.preferred.join('\n');
  sections.responsibilities = blocks.responsibilities.join('\n');
  sections.body = blocks.body.join('\n');
  return sections;
}

function extractInlineSkillPhrases(text, tier) {
  const found = [];
  const seen = new Set();
  const patterns = [
    /(?:experience with|experience in|proficien(?:t|cy) in|knowledge of|familiarity with|skilled in|working knowledge of|hands-on with|background in|expertise in)\s+([^.,;\n]{3,60})/gi,
    /(?:must have|required|preferred|nice to have)\s*:?\s*([^.,;\n]{3,60})/gi
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
          found.push({ skill: token, tier: tier || 50 });
        }
      });
    }
  }
  return found;
}

function extractBulletSkills(text, tier) {
  const found = [];
  const seen = new Set();
  const bulletRe = /(?:^|\n)\s*[-•*]\s+([^\n]{2,100})/g;
  let m;
  while ((m = bulletRe.exec(text)) !== null) {
    const line = m[1].trim();
    // Skip lines that are clearly section titles or very long sentences
    if (/^(requirements?|qualifications?|responsibilities|duties|about the role|job description)\b/i.test(line)) continue;
    // Skip lines that look like sentences (verb at start) not skill phrases
    if (/^(?:manage|lead|develop|create|build|work|support|ensure|provide|assist|maintain|implement|coordinate|communicate|collaborate|partner|design|drive|own|identify|analyze|monitor|review|prepare|handle|perform|deliver|facilitate|conduct|define|establish)/i.test(line)) continue;
    const token = cleanSkillPhrase(line);
    if (!token) continue;
    const key = token.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push({ skill: token, tier: tier || 60 });
    }
  }
  return found;
}

function extractCommaListedSkills(text, tier) {
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
          found.push({ skill: p, tier: tier || 40 });
        }
      });
    });
  }

  const inlineRe = /(?:requirements?|qualifications?|skills?|must have|experience (?:with|in)|proficien(?:t|cy) in|knowledge of)[:\s-]*([^\n]{3,120})/gi;
  while ((m = inlineRe.exec(text)) !== null) {
    const chunk = m[1].replace(/\band\b/gi, ',');
    chunk.split(/[,;|•]/).forEach((part) => {
      const token = cleanSkillPhrase(part);
      if (!token) return;
      const key = token.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        found.push({ skill: token, tier: tier || 40 });
      }
    });
  }

  return found;
}

function skillScore(skill, industry, text, requirementTokens, tier) {
  let score = tier || 50; // base score = tier (lower = higher priority in sort)
  const lower = skill.toLowerCase();
  // Years-of-experience skills already got tier 1 — boost them further for specific-sounding names
  if (requirementTokens && requirementTokens.has(lower)) score -= 10;
  if (isSoftSkill(skill)) score += 50;
  if (industry && getIndustrySkillList(industry).some((s) => s.toLowerCase() === lower)) score -= 10;
  if (getRelatedIndustryKeys(industry).some((rel) => getIndustrySkillList(rel).some((s) => s.toLowerCase() === lower))) score -= 5;
  if (SHARED_TOOLS.some((s) => s.toLowerCase() === lower)) score -= 5;
  if (CERTIFICATION_PATTERNS.some((c) => c.label.toLowerCase() === lower)) score -= 8;
  if (KNOWN_ACRONYMS.some((a) => a.toLowerCase() === lower)) score -= 4;
  return score;
}

function rankSkills(matches, industry, text, requirementTokens) {
  return [...matches].sort((a, b) => {
    const sa = skillScore(a.skill, industry, text, requirementTokens, a.tier);
    const sb = skillScore(b.skill, industry, text, requirementTokens, b.tier);
    if (sa !== sb) return sa - sb;
    return a.skill.length - b.skill.length;
  });
}

function isPreferredSkillPhrase(skill, rawLine) {
  const combined = `${rawLine || ''} ${skill || ''}`;
  return /\b(preferred|nice to have|a plus|plus|desired|optional|bonus)\b/i.test(combined);
}

function buildRequirementTokenSet(skills) {
  const tokens = new Set();
  skills.forEach(({ skill, tier }) => {
    if (tier > 30) return; // only tier 1 / tier 2 items
    const cleaned = cleanSkillPhrase(skill);
    if (!cleaned) return;
    tokens.add(cleaned.toLowerCase());
    cleaned.split(/\s+/).forEach((part) => {
      if (part.length >= 2) tokens.add(part.toLowerCase());
    });
  });
  return tokens;
}

function matchSkills(text, industry) {
  const seen = new Set();
  const matches = [];

  const resolvedIndustry = normalizeIndustry(industry) || inferIndustryFromText(text) || 'general';

  // ── Step 1: Split into sections so we know which tier content comes from ──
  const sections = splitIntoSections(text);

  // ── Step 2: Highest-priority — "N years of X" from the whole JD ──
  for (const skill of extractYearsOfExperience(sections.required || text)) {
    addSkillMatch(matches, seen, skill, 5); // tier 5 = top priority
  }
  // years-of-experience from body too, but lower priority
  if (sections.body) {
    for (const skill of extractYearsOfExperience(sections.body)) {
      addSkillMatch(matches, seen, skill, 15);
    }
  }

  // ── Step 3: Parenthetical skill lists ──
  for (const skill of extractParentheticalSkillLists(sections.required || text)) {
    addSkillMatch(matches, seen, skill, 10);
  }

  // ── Step 4: Bullet points and inline phrases from Required section ──
  for (const item of extractBulletSkills(sections.required, 20)) addSkillMatch(matches, seen, item.skill, item.tier);
  for (const item of extractInlineSkillPhrases(sections.required, 20)) addSkillMatch(matches, seen, item.skill, item.tier);
  for (const item of extractCommaListedSkills(sections.required, 25)) addSkillMatch(matches, seen, item.skill, item.tier);

  // ── Step 5: Certifications and acronyms (document-wide) ──
  for (const token of extractCertifications(text)) addSkillMatch(matches, seen, token, 12);
  for (const token of extractKnownAcronyms(sections.required || text)) addSkillMatch(matches, seen, token, 18);

  // ── Step 6: Preferred / nice-to-have section ──
  for (const item of extractBulletSkills(sections.preferred, 40)) addSkillMatch(matches, seen, item.skill, item.tier);
  for (const item of extractInlineSkillPhrases(sections.preferred, 40)) addSkillMatch(matches, seen, item.skill, item.tier);
  for (const item of extractParentheticalSkillLists(sections.preferred)) addSkillMatch(matches, seen, item, 38);

  // ── Step 7: Responsibilities section (lower priority) ──
  for (const item of extractInlineSkillPhrases(sections.responsibilities, 55)) addSkillMatch(matches, seen, item.skill, item.tier);
  for (const token of extractKnownAcronyms(sections.responsibilities || '')) addSkillMatch(matches, seen, token, 50);

  // ── Step 8: Industry dictionary — only skills that appear in the JD ──
  matchSkillsFromDict(text, getIndustrySkillList(resolvedIndustry), seen, matches, 80, 60);
  for (const relatedKey of getRelatedIndustryKeys(resolvedIndustry)) {
    matchSkillsFromDict(text, getIndustrySkillList(relatedKey), seen, matches, 80, 65);
  }
  matchSkillsFromDict(text, SHARED_TOOLS, seen, matches, 80, 70);
  if (resolvedIndustry !== 'general') {
    matchSkillsFromDict(text, getIndustrySkillList('general'), seen, matches, 80, 75);
  }
  matchSkillsFromDict(text, [...SOFT_SKILLS], seen, matches, 80, 90);

  const requirementTokens = buildRequirementTokenSet(matches);
  const ranked = rankSkills(matches, resolvedIndustry, text, requirementTokens);

  // Deduplicate with subsumption rules:
  // 1. If a skill phrase contains " or " / " and " joining two variants, split it.
  //    e.g. "OSHA 10 or OSHA 30" → ["OSHA 10", "OSHA 30"]
  // 2. Skip a generic shorter form when a more-specific version exists, UNLESS
  //    the shorter form is a recognised acronym/certification (those are always valid).
  const knownAcronymsLower = new Set(KNOWN_ACRONYMS.map((a) => a.toLowerCase()));
  const certLabelsLower = new Set(CERTIFICATION_PATTERNS.map((c) => c.label.toLowerCase()));

  // Expand "X or Y" / "X and Y" skill phrases into separate items
  const expanded = [];
  for (const item of ranked) {
    if (/\b(?:or|and)\b/i.test(item.skill) && item.skill.split(/\s+/).length <= 8) {
      const parts = item.skill.split(/\s+(?:or|and)\s+/i);
      if (parts.length > 1) {
        parts.forEach((p) => {
          const c = cleanSkillPhrase(p.trim());
          if (c) expanded.push({ skill: c, tier: item.tier });
        });
        continue;
      }
    }
    expanded.push(item);
  }

  const expandedLower = expanded.map((r) => r.skill.toLowerCase());
  const deduped = [];
  const rankedSeen = new Set();
  for (const item of expanded) {
    const lower = item.skill.toLowerCase();
    if (rankedSeen.has(lower)) continue;
    // Subsumption: skip a shorter form when a more-specific version exists in the list.
    // Exception: a known acronym/cert is protected from subsumption UNLESS the longer
    // form is itself a recognised cert/acronym (e.g. "CDL" loses to "CDL Class A",
    // "OSHA" loses to "OSHA 10", but "CI/CD" does NOT lose to "CI/CD pipeline").
    // "X certification" / "X certified" phrases are redundant when X itself is a cert label
    const withoutCertSuffix = lower.replace(/\s+certifi(?:cation|ed)$/, '').trim();
    if (withoutCertSuffix !== lower && certLabelsLower.has(withoutCertSuffix)) continue;

    const longerRecognizedExists = expandedLower.some((other) => {
      if (other === lower || !other.startsWith(lower + ' ')) return false;
      return knownAcronymsLower.has(other) || certLabelsLower.has(other);
    });
    if (longerRecognizedExists) continue; // always yield to a more-specific recognised term
    const isProtected = knownAcronymsLower.has(lower) || certLabelsLower.has(lower);
    if (!isProtected) {
      const subsumedByLonger = expandedLower.some((other) =>
        other !== lower && other.startsWith(lower + ' ') && other.length > lower.length
      );
      if (subsumedByLonger) continue;
    }
    rankedSeen.add(lower);
    deduped.push(item.skill);
  }
  return deduped.slice(0, MAX_SUGGESTED_SKILLS);
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

// ─────────────────────────────────────────────────────────────────
// Title-based skill inference — for leads imported with only a job
// title, company, and location (no JD text to parse).
//
// Two passes:
// 1. Technologies named directly in the title ("React Developer",
//    "SQL Server DBA") — scanned against all industry dictionaries.
// 2. Role archetypes: common staffing job titles mapped to the 3-4
//    core skills a recruiter would expect for that role.
//
// Inferred skills are clearly flagged (skills_source) so the RA knows
// they came from the title, not an actual JD, and reviews them.
// ─────────────────────────────────────────────────────────────────
const ROLE_PROFILES = [
  // accounting / finance
  { re: /\b(?:staff |senior |junior )?accountant\b/i, skills: ['general ledger', 'reconciliations', 'QuickBooks'] },
  { re: /\bbookkeeper\b/i, skills: ['bookkeeping', 'QuickBooks', 'accounts payable'] },
  { re: /\bcontroller\b/i, skills: ['GAAP', 'financial reporting', 'month-end close'] },
  { re: /\bpayroll\b/i, skills: ['payroll processing', 'ADP', 'multi-state payroll'] },
  { re: /\b(?:accounts payable|ap) (?:specialist|clerk|manager)\b/i, skills: ['accounts payable', 'invoice processing', 'vendor management'] },
  { re: /\b(?:accounts receivable|ar) (?:specialist|clerk|manager)\b/i, skills: ['accounts receivable', 'collections', 'billing'] },
  { re: /\btax (?:preparer|accountant|manager|associate)\b/i, skills: ['tax preparation', 'CPA', 'tax compliance'] },
  { re: /\bauditor\b/i, skills: ['audit', 'GAAP', 'internal controls'] },
  { re: /\bfinancial analyst\b/i, skills: ['financial modeling', 'Excel', 'FP&A'] },
  { re: /\bcfo\b/i, skills: ['financial strategy', 'GAAP', 'forecasting'] },

  // healthcare
  { re: /\b(?:registered nurse|rn)\b/i, skills: ['patient care', 'EHR', 'medication administration'] },
  { re: /\b(?:lpn|licensed practical nurse)\b/i, skills: ['patient care', 'vital signs', 'medication administration'] },
  { re: /\b(?:cna|nursing assistant)\b/i, skills: ['patient care', 'vital signs', 'ADLs'] },
  { re: /\bmedical (?:biller|billing)\b/i, skills: ['medical billing', 'ICD-10', 'CPT coding'] },
  { re: /\bmedical (?:coder|coding)\b/i, skills: ['ICD-10', 'CPT coding', 'medical records'] },
  { re: /\bmedical assistant\b/i, skills: ['patient intake', 'vital signs', 'EHR'] },
  { re: /\bphlebotomist\b/i, skills: ['phlebotomy', 'specimen collection', 'patient care'] },
  { re: /\bphysical therapist\b/i, skills: ['physical therapy', 'patient evaluation', 'treatment planning'] },

  // logistics / warehouse / driving
  { re: /\bwarehouse (?:manager|supervisor|lead|associate|worker)\b/i, skills: ['inventory control', 'WMS', 'shipping and receiving'] },
  { re: /\bforklift\b/i, skills: ['forklift operation', 'inventory control', 'pallet jack'] },
  { re: /\b(?:truck |delivery |cdl )?driver\b/i, skills: ['CDL', 'DOT compliance', 'route planning'] },
  { re: /\bdispatcher\b/i, skills: ['dispatch', 'route planning', 'TMS'] },
  { re: /\blogistics (?:coordinator|manager|specialist)\b/i, skills: ['logistics coordination', 'TMS', 'freight management'] },
  { re: /\bsupply chain\b/i, skills: ['supply chain management', 'demand planning', 'ERP'] },
  { re: /\b(?:freight|import|export) (?:coordinator|specialist|agent)\b/i, skills: ['freight forwarding', 'customs documentation', 'Incoterms'] },

  // construction / trades
  { re: /\bhvac\b/i, skills: ['HVAC systems', 'EPA 608', 'preventive maintenance'] },
  { re: /\belectrician\b/i, skills: ['electrical systems', 'NEC code', 'troubleshooting'] },
  { re: /\bplumber\b/i, skills: ['plumbing systems', 'pipe fitting', 'blueprint reading'] },
  { re: /\bcarpenter\b/i, skills: ['carpentry', 'framing', 'blueprint reading'] },
  { re: /\bwelder\b/i, skills: ['MIG welding', 'TIG welding', 'blueprint reading'] },
  { re: /\b(?:construction )?superintendent\b/i, skills: ['construction management', 'scheduling', 'OSHA 30'] },
  { re: /\bproject manager\b.*\bconstruction\b|\bconstruction\b.*\bproject manager\b/i, skills: ['construction management', 'Procore', 'budgeting'] },
  { re: /\bestimator\b/i, skills: ['cost estimating', 'takeoffs', 'blueprint reading'] },
  { re: /\bmaintenance technician\b/i, skills: ['preventive maintenance', 'troubleshooting', 'HVAC'] },

  // manufacturing
  { re: /\bcnc (?:machinist|operator|programmer)\b/i, skills: ['CNC machining', 'G-code', 'blueprint reading'] },
  { re: /\bmachinist\b/i, skills: ['CNC machining', 'manual machining', 'GD&T'] },
  { re: /\b(?:production|plant) (?:manager|supervisor)\b/i, skills: ['production scheduling', 'lean manufacturing', 'team leadership'] },
  { re: /\bquality (?:engineer|inspector|manager)\b/i, skills: ['quality control', 'ISO 9001', 'root cause analysis'] },
  { re: /\bassembl(?:er|y)\b/i, skills: ['assembly', 'blueprint reading', 'hand tools'] },

  // technology — stack-specific first, generic after
  { re: /\b(?:react|angular|vue)(?:\.?js)? (?:engineer|developer)\b/i, skills: ['JavaScript', 'TypeScript', 'CSS'] },
  { re: /\b(?:node|java|python|php|\.net|c#|golang|go|ruby) (?:engineer|developer)\b/i, skills: ['API development', 'SQL', 'Git'] },
  { re: /\b(?:software|backend|back-end|full.?stack|web|application) (?:engineer|developer)\b/i, skills: ['JavaScript', 'SQL', 'API development'] },
  { re: /\bfront.?end (?:engineer|developer)\b/i, skills: ['JavaScript', 'React', 'CSS'] },
  { re: /\bdata (?:engineer|analyst|scientist)\b/i, skills: ['SQL', 'Python', 'data pipelines'] },
  { re: /\bdevops\b/i, skills: ['CI/CD', 'AWS', 'Kubernetes'] },
  { re: /\b(?:qa|quality assurance) (?:engineer|analyst|tester)\b/i, skills: ['test automation', 'Selenium', 'regression testing'] },
  { re: /\b(?:it|desktop|technical) support\b/i, skills: ['troubleshooting', 'Active Directory', 'help desk'] },
  { re: /\b(?:network|systems?) (?:engineer|administrator|admin)\b/i, skills: ['networking', 'Windows Server', 'Active Directory'] },
  { re: /\bdba\b|\bdatabase administrator\b/i, skills: ['SQL Server', 'database administration', 'performance tuning'] },

  // sales / admin / office
  { re: /\b(?:sales|account) (?:representative|rep|executive|manager)\b/i, skills: ['B2B sales', 'CRM', 'pipeline management'] },
  { re: /\bbusiness development\b/i, skills: ['lead generation', 'CRM', 'client relationships'] },
  { re: /\bcustomer (?:service|support) (?:representative|rep|specialist)?\b/i, skills: ['customer service', 'CRM', 'conflict resolution'] },
  { re: /\b(?:administrative|executive) assistant\b/i, skills: ['calendar management', 'Microsoft Office', 'travel coordination'] },
  { re: /\boffice manager\b/i, skills: ['office administration', 'Microsoft Office', 'vendor management'] },
  { re: /\breceptionist\b/i, skills: ['front desk', 'phone systems', 'scheduling'] },
  { re: /\b(?:hr|human resources) (?:generalist|manager|coordinator|specialist)\b/i, skills: ['employee relations', 'HRIS', 'onboarding'] },
  { re: /\brecruiter\b/i, skills: ['full-cycle recruiting', 'ATS', 'candidate sourcing'] },
  { re: /\bparalegal\b/i, skills: ['legal research', 'document preparation', 'e-discovery'] },
  { re: /\blegal assistant\b/i, skills: ['legal documentation', 'calendaring', 'client communication'] },

  // hospitality / food
  { re: /\b(?:executive |sous |head )?chef\b/i, skills: ['menu planning', 'food safety', 'kitchen management'] },
  { re: /\b(?:restaurant|food service) manager\b/i, skills: ['restaurant operations', 'food safety', 'staff scheduling'] },
  { re: /\bhotel (?:manager|general manager)\b/i, skills: ['hotel operations', 'PMS', 'guest relations'] },

  // automotive
  { re: /\bautomotive technician\b|\bauto mechanic\b/i, skills: ['automotive diagnostics', 'ASE certification', 'OBD-II'] },
  { re: /\bservice advisor\b/i, skills: ['service writing', 'customer service', 'DMS'] }
];

/**
 * Infer skills from a job title alone — used when a lead is imported
 * without any JD text. Returns [] if nothing can be inferred.
 */
function inferSkillsFromTitle(title, industry) {
  if (!title || !String(title).trim()) return [];
  const t = String(title).trim();
  const found = [];
  const seen = new Set();

  const push = (skill) => {
    const key = String(skill).toLowerCase();
    if (!seen.has(key)) { seen.add(key); found.push(skill); }
  };

  // Pass 1: technologies named directly in the title (e.g. "React Developer",
  // "SQL Server DBA", "Salesforce Administrator"). Scan every dictionary —
  // titles are short so this is cheap.
  const resolvedIndustry = normalizeIndustry(industry);
  const dictsToScan = resolvedIndustry
    ? [resolvedIndustry, ...getRelatedIndustryKeys(resolvedIndustry), 'general']
    : Object.keys(SKILL_DICTIONARIES);
  for (const key of dictsToScan) {
    for (const skill of getIndustrySkillList(key)) {
      if (skill.length >= 3 && skillInText(skill, t)) push(skill);
    }
  }
  for (const tool of SHARED_TOOLS) {
    if (tool.length >= 3 && skillInText(tool, t)) push(tool);
  }

  // Pass 2: role archetype mapping
  for (const profile of ROLE_PROFILES) {
    if (profile.re.test(t)) {
      profile.skills.forEach(push);
      break; // first matching profile wins — they're ordered specific → generic
    }
  }

  // Subsumption dedup: drop "CDL" when "CDL Class A" is present, etc.
  const lowers = found.map((s) => s.toLowerCase());
  const deduped = found.filter((skill) => {
    const lower = skill.toLowerCase();
    return !lowers.some((other) => other !== lower && other.startsWith(lower + ' '));
  });

  return deduped.slice(0, MAX_SUGGESTED_SKILLS);
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

  // No JD text (or it produced almost nothing)? Infer skills from the title.
  // Flag the source so the RA knows these are educated guesses to review,
  // not extracted requirements.
  if (parsed.suggested_skills.length < 3 && position) {
    const inferred = inferSkillsFromTitle(position, industry);
    if (inferred.length) {
      const merged = [...parsed.suggested_skills];
      const seen = new Set(merged.map((s) => s.toLowerCase()));
      for (const skill of inferred) {
        if (merged.length >= MAX_SUGGESTED_SKILLS) break;
        if (!seen.has(skill.toLowerCase())) { seen.add(skill.toLowerCase()); merged.push(skill); }
      }
      parsed.skills = merged;
      parsed.suggested_skills = merged;
      parsed.skill_1 = merged[0] || '';
      parsed.skill_2 = merged[1] || '';
      parsed.skill_3 = merged[2] || '';
      parsed.skills_source = 'title_inference';
    }
  }

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
  inferSkillsFromTitle,
  SKILL_DICTIONARIES,
  SOFT_SKILLS,
  SHARED_TOOLS,
  RELATED_INDUSTRIES,
  buildResearchFromLeadData,
  MAX_SUGGESTED_SKILLS
};
