-- ═══════════════════════════════════════════════════════════════
-- FUTE GLOBAL LLC — Lead Management Software
-- Run this in: Supabase → SQL Editor → New Query → Run
-- ═══════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL DEFAULT 'change_me',
  role TEXT NOT NULL CHECK (role IN ('admin','bd','ra')),
  employee_id TEXT UNIQUE,
  designation TEXT,
  assigned_bdm_id UUID,
  platform TEXT DEFAULT 'Gmail',
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  deleted_at TIMESTAMPTZ DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS companies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  website TEXT,
  industry TEXT,
  location TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  deleted_at TIMESTAMPTZ DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS leads (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  company_id UUID REFERENCES companies(id) ON DELETE SET NULL,
  position TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT,
  designation TEXT,
  email TEXT,
  phone TEXT,
  linkedin TEXT,
  source TEXT DEFAULT 'LinkedIn',
  stage TEXT NOT NULL DEFAULT 'Active',
  analyst_id UUID REFERENCES users(id) ON DELETE SET NULL,
  bdm_id UUID REFERENCES users(id) ON DELETE SET NULL,
  notes TEXT DEFAULT '',
  email_sent_at DATE,
  email_platform TEXT,
  lead_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  deleted_at TIMESTAMPTZ DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  lead_id UUID REFERENCES leads(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  is_primary BOOLEAN DEFAULT FALSE,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS emails (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  lead_id UUID REFERENCES leads(id) ON DELETE CASCADE,
  sent_by UUID REFERENCES users(id) ON DELETE SET NULL,
  to_email TEXT NOT NULL,
  subject TEXT,
  body TEXT,
  platform TEXT DEFAULT 'Gmail',
  status TEXT DEFAULT 'sent',
  sent_at DATE DEFAULT CURRENT_DATE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activity_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  lead_id UUID REFERENCES leads(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action_type TEXT NOT NULL,
  description TEXT,
  old_value JSONB,
  new_value JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reminders (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  lead_id UUID REFERENCES leads(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  contact_name TEXT,
  company_name TEXT,
  email TEXT,
  return_date DATE NOT NULL,
  reminder_time TIME DEFAULT '09:00',
  note TEXT,
  status TEXT DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_templates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT DEFAULT 'Default',
  subject TEXT,
  body TEXT,
  is_global BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_leads_analyst ON leads(analyst_id);
CREATE INDEX IF NOT EXISTS idx_leads_bdm ON leads(bdm_id);
CREATE INDEX IF NOT EXISTS idx_leads_date ON leads(lead_date);
CREATE INDEX IF NOT EXISTS idx_leads_stage ON leads(stage);
CREATE INDEX IF NOT EXISTS idx_leads_deleted ON leads(deleted_at);
CREATE INDEX IF NOT EXISTS idx_activity_lead ON activity_log(lead_id);
CREATE INDEX IF NOT EXISTS idx_reminders_user ON reminders(user_id);

-- RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE reminders ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_all_users" ON users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_companies" ON companies FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_leads" ON leads FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_contacts" ON contacts FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_emails" ON emails FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_activity" ON activity_log FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_reminders" ON reminders FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_templates" ON email_templates FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Seed users (password = Fute@2024)
INSERT INTO users (id,name,email,password_hash,role,employee_id,designation,platform) VALUES
('11111111-0001-0001-0001-000000000001','Prince Thomas','prince@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','admin','FG-001','Business Development Manager','Gmail'),
('11111111-0001-0001-0001-000000000002','Ash','ash@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','bd','FG-002','Business Development Manager','Gmail'),
('11111111-0001-0001-0001-000000000003','Pranay','pranay@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','bd','FG-003','Business Development Manager','Outlook'),
('11111111-0001-0001-0001-000000000004','Andy','andy@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','bd','FG-004','Business Development Manager','Gmail'),
('11111111-0001-0001-0001-000000000005','Sarah','sarah@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','bd','FG-005','Business Development Manager','Outlook'),
('11111111-0001-0001-0001-000000000006','Mick Thompson','mick@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-006','Research Analyst','Gmail'),
('11111111-0001-0001-0001-000000000007','Neal Patrick','neal@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-007','Research Analyst','Gmail'),
('11111111-0001-0001-0001-000000000008','Lisa Anderson','lisa@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-008','Research Analyst','Outlook'),
('11111111-0001-0001-0001-000000000009','Daniel James','daniel@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-009','Research Analyst','Gmail'),
('11111111-0001-0001-0001-000000000010','Karen','karen@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-010','Research Analyst','Gmail'),
('11111111-0001-0001-0001-000000000011','Kristy Scott','kristy@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-011','Research Analyst','Outlook'),
('11111111-0001-0001-0001-000000000012','Justin','justin@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-012','Research Analyst','Gmail'),
('11111111-0001-0001-0001-000000000013','Spencer Brown','spencer@futeglobal.com','$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p690WkBV4BdnqpSEHmAW4y','ra','FG-013','Research Analyst','Gmail')
ON CONFLICT (email) DO NOTHING;

UPDATE users SET assigned_bdm_id='11111111-0001-0001-0001-000000000001' WHERE employee_id IN ('FG-006','FG-007','FG-008','FG-009');
UPDATE users SET assigned_bdm_id='11111111-0001-0001-0001-000000000002' WHERE employee_id='FG-010';
UPDATE users SET assigned_bdm_id='11111111-0001-0001-0001-000000000003' WHERE employee_id='FG-011';
UPDATE users SET assigned_bdm_id='11111111-0001-0001-0001-000000000004' WHERE employee_id='FG-012';
UPDATE users SET assigned_bdm_id='11111111-0001-0001-0001-000000000005' WHERE employee_id='FG-013';

INSERT INTO email_templates (name,subject,body,is_global) VALUES
('Default Outreach',
 'Opportunity regarding {{pos}} at {{company}}',
 E'Hi {{fn}},\n\nI came across {{company}} and was really impressed by what you''re building in the {{ind}} space.\n\nAt Fute Global, we specialize in connecting organizations with top-tier talent. Given your role as {{desig}}, I believe we could be genuinely helpful with your {{pos}} search.\n\nWould you be open to a quick 15-minute call this week?\n\nWarm regards,\n{{sender}}\nFute Global LLC',
 TRUE)
ON CONFLICT DO NOTHING;
