/**
 * Industry skill dictionaries aligned with Fute LMS INDUSTRIES list.
 * Matched using word boundaries against pasted job descriptions.
 */

const SKILL_DICTIONARIES = {
  accounting: [
    'CCH', 'QuickBooks', 'CPA', 'GAAP', 'tax preparation', 'trust and estate',
    'bookkeeping', 'audit', 'Sage', 'Xero', 'ProSeries', 'Lacerte', 'UltraTax', 'payroll',
    'accounts payable', 'accounts receivable', 'financial reporting', 'Excel', 'tax compliance',
    'general ledger', 'reconciliation', 'NetSuite', 'Intacct', 'FAS', 'cost accounting'
  ],
  advertising: [
    'Google Ads', 'Facebook Ads', 'media buying', 'copywriting', 'brand strategy',
    'public relations', 'press release', 'campaign management', 'SEO', 'SEM',
    'content marketing', 'Adobe Creative Suite', 'media planning', 'influencer marketing',
    'HubSpot', 'Marketo', 'social media', 'paid media', 'programmatic advertising'
  ],
  agriculture: [
    'crop management', 'irrigation', 'agronomy', 'pesticide application', 'soil science',
    'farm management', 'livestock', 'harvesting', 'precision agriculture', 'GIS',
    'agricultural equipment', 'food safety', 'USDA', 'crop scouting', 'fertilization'
  ],
  aviation: [
    'FAA', 'A&P license', 'avionics', 'aircraft maintenance', 'Part 135', 'Part 121',
    'ATP', 'CFI', 'dispatch', 'ground operations', 'cargo', 'DOT', 'IATA', 'flight operations',
    'aviation safety', 'MRO', 'logbook', 'airframe', 'powerplant'
  ],
  construction: [
    'OSHA 30', 'OSHA 10', 'blueprint reading', 'estimating', 'Procore', 'heavy equipment',
    'commercial construction', 'residential construction', 'project superintendent',
    'site superintendent', 'framing', 'concrete', 'civil', 'AutoCAD', 'Revit',
    'MEP', 'takeoffs', 'subcontractor management', 'AIA contracts', 'SketchUp',
    'building materials', 'structural', 'architectural drawings', 'LEED'
  ],
  creative: [
    'Adobe Photoshop', 'Adobe Illustrator', 'InDesign', 'Lightroom', 'photography',
    'videography', 'Final Cut Pro', 'Premiere Pro', 'After Effects', 'copywriting',
    'editorial', 'journalism', 'AP style', 'content creation', 'graphic design',
    'UI design', 'Figma', 'Canva', 'motion graphics'
  ],
  automotive: [
    'ASE certification', 'diagnostics', 'OBD-II', 'transmission', 'brake systems',
    'engine repair', 'dealership', 'CDK', 'Reynolds & Reynolds', 'F&I', 'detailing',
    'service advisor', 'parts inventory', 'collision repair', 'alignment', 'electrical systems',
    'hybrid vehicles', 'fleet management', 'DMS'
  ],
  banking: [
    'AML', 'KYC', 'BSA', 'underwriting', 'loan origination', 'credit analysis',
    'Salesforce', 'Bloomberg', 'risk management', 'compliance', 'FINRA', 'Series 7',
    'Series 63', 'wire transfers', 'teller operations', 'mortgage', 'HMDA',
    'core banking', 'Fiserv', 'Jack Henry', 'treasury management', 'commercial banking'
  ],
  biotech: [
    'GMP', 'FDA', 'clinical trials', 'PCR', 'HPLC', 'cell culture', 'regulatory affairs',
    'IND', 'NDA', 'validation', 'pharmacovigilance', 'biostatistics', 'R&D',
    'laboratory', 'assay development', 'bioinformatics', 'SOP', 'ICH guidelines',
    'protein purification', 'flow cytometry', 'ELISA'
  ],
  media: [
    'video production', 'audio editing', 'broadcast journalism', 'live streaming',
    'Avid', 'Adobe Premiere', 'camera operation', 'lighting', 'sound design',
    'post-production', 'content management', 'CMS', 'digital media', 'print production',
    'offset printing', 'prepress', 'media relations', 'social media management'
  ],
  chemical: [
    'chemical engineering', 'process safety', 'HAZMAT', 'ISO 14001', 'EPA regulations',
    'chemical handling', 'laboratory', 'quality control', 'Six Sigma', 'OSHA',
    'polymer chemistry', 'R&D', 'process improvement', 'SAP', 'batch records',
    'industrial hygiene', 'wastewater', 'environmental compliance'
  ],
  technology: [
    'JavaScript', 'Python', 'Java', 'React', 'Node.js', 'AWS', 'Azure', 'SQL', 'Kubernetes',
    'Docker', 'TypeScript', '.NET', 'C#', 'Angular', 'Vue', 'DevOps', 'CI/CD',
    'REST API', 'Git', 'Linux', 'Go', 'Rust', 'Swift', 'Kotlin', 'Flutter',
    'machine learning', 'data engineering', 'Terraform', 'Ansible', 'Spark', 'Kafka',
    'hardware design', 'FPGA', 'embedded systems', 'PCB design', 'firmware'
  ],
  consulting: [
    'project management', 'PMP', 'business analysis', 'stakeholder management',
    'process improvement', 'change management', 'Six Sigma', 'Lean', 'Agile',
    'requirements gathering', 'Visio', 'PowerPoint', 'data analysis', 'ERP',
    'SAP', 'Oracle', 'Salesforce', 'strategy', 'client engagement', 'RFP'
  ],
  retail: [
    'POS', 'inventory management', 'merchandising', 'customer service', 'store management',
    'planogram', 'loss prevention', 'visual merchandising', 'retail sales', 'SKU',
    'demand planning', 'replenishment', 'e-commerce', 'Shopify', 'omnichannel',
    'category management', 'vendor management', 'shrinkage', 'Nielsen'
  ],
  mortgage: [
    'loan origination', 'underwriting', 'RESPA', 'TILA', 'NMLS', 'FHA', 'VA loans',
    'conventional loans', 'mortgage processing', 'title insurance', 'escrow',
    'credit analysis', 'debt collections', 'skip tracing', 'FDCPA', 'Encompass',
    'Calyx Point', 'appraisal', 'credit scoring', 'loss mitigation'
  ],
  defense: [
    'security clearance', 'DoD', 'ITAR', 'systems engineering', 'CMMC', 'NIST',
    'program management', 'defense contracts', 'FAR', 'DFARS', 'logistics',
    'aerospace engineering', 'CAD', 'CATIA', 'systems integration', 'test & evaluation',
    'radar', 'avionics', 'proposal writing', 'government contracting'
  ],
  education: [
    'curriculum development', 'lesson planning', 'classroom management', 'IEP',
    'special education', 'instructional design', 'LMS', 'Blackboard', 'Canvas',
    'TESOL', 'ESL', 'tutoring', 'student assessment', 'differentiated instruction',
    'Google Classroom', 'STEM', 'early childhood', 'adult education', 'library science'
  ],
  electronics: [
    'circuit design', 'PCB layout', 'FPGA', 'VHDL', 'Verilog', 'semiconductor',
    'wafer fabrication', 'embedded systems', 'signal processing', 'oscilloscope',
    'soldering', 'ESD', 'test engineering', 'failure analysis', 'Altium',
    'microcontroller', 'analog design', 'RF engineering', 'power electronics'
  ],
  staffing: [
    'full-cycle recruiting', 'ATS', 'Bullhorn', 'sourcing', 'LinkedIn Recruiter',
    'Boolean search', 'candidate screening', 'onboarding', 'job boards', 'Indeed',
    'talent acquisition', 'workforce planning', 'background checks', 'offer negotiation',
    'HR compliance', 'HRIS', 'Workday', 'contract staffing', 'permanent placement'
  ],
  energy: [
    'oil & gas', 'upstream', 'downstream', 'drilling', 'pipeline', 'refinery',
    'P&ID', 'process engineering', 'utilities', 'power generation', 'renewable energy',
    'solar', 'wind energy', 'electrical engineering', 'substation', 'SCADA',
    'natural gas', 'petroleum engineering', 'HSE', 'regulatory compliance'
  ],
  entertainment: [
    'event management', 'production management', 'talent management', 'booking',
    'venue management', 'ticketing', 'AV technology', 'stage management',
    'content creation', 'streaming', 'game design', 'Unity', 'Unreal Engine',
    'social media', 'sponsorship', 'sports management', 'recreation programming'
  ],
  environmental: [
    'environmental compliance', 'EPA', 'NEPA', 'remediation', 'Phase I ESA',
    'air quality', 'stormwater management', 'RCRA', 'CERCLA', 'GIS', 'AutoCAD',
    'environmental science', 'sustainability', 'ISO 14001', 'EHS', 'permitting',
    'soil sampling', 'groundwater', 'hazardous waste', 'ecological assessment'
  ],
  fashion: [
    'fashion design', 'pattern making', 'garment construction', 'CAD', 'Adobe Illustrator',
    'textile sourcing', 'production planning', 'PLM', 'trend forecasting',
    'retail buying', 'merchandising', 'product development', 'supply chain',
    'overseas manufacturing', 'quality control', 'technical design', 'spec sheets'
  ],
  food: [
    'food safety', 'ServSafe', 'HACCP', 'kitchen management', 'menu development',
    'culinary arts', 'food cost', 'inventory management', 'restaurant management',
    'POS systems', 'catering', 'banquet operations', 'allergen awareness',
    'sanitation', 'food production', 'food manufacturing', 'FDA regulations'
  ],
  funeral: [
    'funeral director', 'embalming', 'cremation', 'funeral service', 'grief counseling',
    'preneed', 'burial', 'state licensure', 'mortuary science', 'family services',
    'funeral home management', 'OSHA', 'cemetery operations', 'monument sales'
  ],
  government: [
    'government contracting', 'public administration', 'policy analysis', 'grant writing',
    'FEMA', 'GS rating', 'security clearance', 'federal regulations', 'procurement',
    'FAR', 'budget management', 'FOIA', 'compliance', 'municipal government',
    'public health', 'emergency management', 'civil service'
  ],
  healthcare: [
    'RN', 'LPN', 'BLS', 'ACLS', 'EHR', 'Epic', 'Cerner', 'med-surg', 'ICU', 'CNA',
    'patient care', 'clinical', 'phlebotomy', 'HIPAA', 'medical coding', 'ICD-10',
    'CPT codes', 'prior authorization', 'medical billing', 'case management',
    'nursing', 'physician', 'physical therapy', 'occupational therapy', 'radiology'
  ],
  realestate: [
    'real estate license', 'MLS', 'Salesforce', 'property management', 'leasing',
    'homebuilding', 'land acquisition', 'closing', 'title', 'escrow',
    'commercial real estate', 'residential sales', 'CRM', 'Yardi', 'AppFolio',
    'HOA management', 'construction management', 'Procore', 'entitlements', 'zoning'
  ],
  hospitality: [
    'hotel management', 'front desk', 'PMS', 'Opera', 'guest services', 'F&B',
    'banquet management', 'revenue management', 'housekeeping', 'concierge',
    'hospitality management', 'catering', 'event planning', 'STR', 'OTA',
    'customer service', 'tourism', 'resort operations', 'yield management'
  ],
  hvac: [
    'EPA 608', 'NATE', 'refrigeration', 'HVAC', 'commercial HVAC', 'residential HVAC',
    'chiller', 'boiler', 'VFD', 'BAS', 'ductwork', 'sheet metal', 'controls',
    'heat pump', 'air handler', 'RTU', 'building automation', 'Trane', 'Carrier',
    'preventive maintenance', 'service technician', 'load calculations'
  ],
  importexport: [
    'import compliance', 'export compliance', 'customs brokerage', 'Incoterms',
    'freight forwarding', 'logistics', 'supply chain', 'HS codes', 'CBP',
    'trade compliance', 'letters of credit', 'international trade', 'ERP',
    'ocean freight', 'air freight', 'customs clearance', 'tariff classification'
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
  insurance: [
    'underwriting', 'claims adjuster', 'policy administration', 'actuarial',
    'life insurance', 'P&C', 'health insurance', 'reinsurance', 'risk management',
    'insurance sales', 'Guidewire', 'Duck Creek', 'EPIC', 'licensed agent',
    'managed care', 'utilization review', 'benefits administration', 'ERISA'
  ],
  ecommerce: [
    'Shopify', 'WooCommerce', 'Amazon Seller', 'digital marketing', 'SEO', 'SEM',
    'Google Analytics', 'conversion rate optimization', 'email marketing',
    'product listings', 'marketplace management', 'Magento', 'BigCommerce',
    'paid social', 'A/B testing', 'UX design', 'web analytics', 'customer acquisition'
  ],
  landscaping: [
    'landscape design', 'horticulture', 'irrigation', 'hardscape', 'softscape',
    'lawn care', 'pesticide license', 'tree service', 'arborist', 'snow removal',
    'landscape maintenance', 'commercial landscaping', 'residential landscaping',
    'plant identification', 'sod installation', 'drainage'
  ],
  legal: [
    'litigation', 'corporate law', 'contracts', 'paralegal', 'e-discovery', 'compliance',
    'criminal law', 'family law', 'immigration law', 'legal research', 'Westlaw', 'LexisNexis',
    'depositions', 'motions', 'law enforcement', 'investigations', 'security management',
    'physical security', 'loss prevention', 'CPL', 'background investigations'
  ],
  manufacturing: [
    'lean manufacturing', 'Six Sigma', 'CNC', 'PLC', 'ISO 9001', 'quality control',
    'production', 'assembly', 'maintenance', 'AutoCAD', 'SolidWorks', 'GD&T',
    'tooling', 'machining', 'welding', 'injection molding', 'stamping',
    'ERP', 'SAP', 'Kaizen', '5S', 'APQP', 'PPAP', 'FMEA', 'MRP'
  ],
  medicaldevice: [
    'medical devices', 'FDA 510(k)', 'ISO 13485', 'design controls', 'V&V',
    'biocompatibility', 'sterilization', 'regulatory affairs', 'quality systems',
    'CAPA', 'DHF', 'clinical sales', 'capital equipment', 'field service',
    'surgical instruments', 'imaging', 'electrophysiology', 'orthopedics'
  ],
  nonprofit: [
    'grant writing', 'fundraising', 'donor relations', 'program management',
    'case management', 'social work', 'community outreach', 'volunteer management',
    'nonprofit management', 'advocacy', "501(c)(3)", "Raiser's Edge", 'Salesforce',
    'event planning', 'board relations', 'impact measurement', 'LCSW', 'MSW'
  ],
  officesupplies: [
    'B2B sales', 'account management', 'procurement', 'vendor management',
    'office equipment', 'copier sales', 'managed print services', 'customer service',
    'inventory management', 'ERP', 'territory management', 'contract negotiation'
  ],
  packaging: [
    'packaging design', 'structural packaging', 'CAD', 'ArtiosCAD', 'corrugated',
    'flexographic printing', 'packaging engineering', 'supply chain', 'SQF',
    'BRC', 'packaging materials', 'sustainability', 'cost reduction',
    'project management', 'vendor management', 'quality control'
  ],
  sales: [
    'Salesforce', 'CRM', 'B2B sales', 'B2C sales', 'account management',
    'cold calling', 'lead generation', 'pipeline management', 'HubSpot',
    'digital marketing', 'email marketing', 'SEO', 'Google Analytics',
    'territory management', 'quota attainment', 'product marketing', 'market research',
    'brand management', 'content strategy', 'demand generation'
  ],
  securities: [
    'Series 7', 'Series 63', 'Series 65', 'Series 66', 'FINRA', 'SEC',
    'equity research', 'fixed income', 'portfolio management', 'Bloomberg',
    'options trading', 'derivatives', 'investment banking', 'wealth management',
    'financial planning', 'AML', 'KYC', 'compliance', 'prime brokerage'
  ],
  telecom: [
    'wireless networks', '5G', 'LTE', 'RF engineering', 'tower climbing',
    'telecommunications', 'VoIP', 'PBX', 'network engineering', 'Cisco',
    'social media management', 'content creation', 'community management',
    'Instagram', 'TikTok', 'Facebook', 'Twitter', 'analytics', 'paid social'
  ],
  travel: [
    'travel management', 'GDS', 'Sabre', 'Amadeus', 'Worldspan', 'travel booking',
    'corporate travel', 'IATA', 'tour operations', 'travel agency', 'ticketing',
    'visa processing', 'travel consulting', 'hospitality', 'customer service',
    'expense management', 'Concur', 'travel policy'
  ],
  /** Professional tools only — soft skills handled separately in jd-parser */
  general: [
    'Microsoft Office', 'Excel', 'Word', 'Outlook', 'PowerPoint', 'Google Workspace',
    'data analysis', 'reporting', 'budgeting', 'documentation', 'scheduling', 'data entry'
  ]
};

module.exports = { SKILL_DICTIONARIES };
