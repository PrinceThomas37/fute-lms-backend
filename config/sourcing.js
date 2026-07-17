// ============================================================================
// Sourcing provider registry
// ----------------------------------------------------------------------------
// The catalogue of candidate-sourcing providers. `file` (CSV/XLSX) works today
// with no third-party credentials; `api` providers are scaffolded and report
// `needs_credentials` until a real adapter + key is wired. See
// docs/SOURCING_AND_SCHEDULING_PLAN.md. Legitimate API connectors only — the
// framework never scrapes a board.
// ============================================================================

const PROVIDERS = [
  { id: 'csv',           label: 'CSV / File Import', kind: 'file', note: 'Export candidates from any job board and import here — works for every board.' },
  { id: 'apollo',        label: 'Apollo',            kind: 'api',  note: 'People-search API. Add your Apollo key on the Integrations page.' },
  { id: 'indeed',        label: 'Indeed',            kind: 'api',  note: 'Needs an Indeed employer/API account.' },
  { id: 'monster',       label: 'Monster',           kind: 'api',  note: 'Needs a Monster account with API access.' },
  { id: 'careerbuilder', label: 'CareerBuilder',     kind: 'api',  note: 'Needs CareerBuilder API credentials.' },
  { id: 'dice',          label: 'Dice',              kind: 'api',  note: 'Needs Dice API credentials.' },
  { id: 'linkedin',      label: 'LinkedIn (Talent)', kind: 'api',  note: 'Requires LinkedIn Talent Solutions partner access.' },
];

const PROVIDER_IDS = PROVIDERS.map(p => p.id);

// Availability today: file providers are ready; api providers await a wired
// adapter + configured credentials (none implemented yet in Slice A).
function providerList() {
  return PROVIDERS.map(p => ({
    id: p.id,
    label: p.label,
    kind: p.kind,
    note: p.note,
    available: p.kind === 'file',
    status: p.kind === 'file' ? 'ready' : 'needs_credentials',
  }));
}

module.exports = { PROVIDERS, PROVIDER_IDS, providerList };
