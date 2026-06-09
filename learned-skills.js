/**
 * Runtime-learned skills merged into industry dictionaries.
 * Updated when RAs save leads/research with skills not already in the base dictionary.
 */

const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, 'learned-skills.json');

function loadLearnedSkills() {
  try {
    if (!fs.existsSync(FILE)) return {};
    const raw = fs.readFileSync(FILE, 'utf8').trim();
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveLearnedSkills(data) {
  fs.writeFileSync(FILE, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function learnSkillsForIndustry(industryKey, skills) {
  if (!industryKey || !Array.isArray(skills) || !skills.length) return false;
  const learned = loadLearnedSkills();
  const bucket = learned[industryKey] || [];
  const seen = new Set(bucket.map((s) => String(s).toLowerCase()));
  let changed = false;
  skills.forEach((skill) => {
    const cleaned = String(skill || '').trim();
    if (!cleaned || cleaned.length < 2 || cleaned.length > 60) return;
    const key = cleaned.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    bucket.push(cleaned);
    changed = true;
  });
  if (!changed) return false;
  learned[industryKey] = bucket;
  saveLearnedSkills(learned);
  return true;
}

module.exports = { loadLearnedSkills, saveLearnedSkills, learnSkillsForIndustry, LEARNED_SKILLS_FILE: FILE };
