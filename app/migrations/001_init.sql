CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
  daily_limit INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL,
  username TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts(ip, username, attempted_at);

CREATE TABLE IF NOT EXISTS proxies (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('http','https','socks4','socks4a','socks5','socks5h')),
  username TEXT,
  password_enc BLOB,
  label TEXT,
  status TEXT NOT NULL DEFAULT 'unchecked' CHECK (status IN ('unchecked','alive','dead')),
  last_checked_at TEXT,
  latency_ms INTEGER,
  exit_ip TEXT,
  country TEXT,
  country_code TEXT,
  region TEXT,
  city TEXT,
  isp TEXT,
  org TEXT,
  asn TEXT,
  anonymity TEXT CHECK (anonymity IN ('transparent','anonymous','elite')),
  risk_score INTEGER,
  is_public_proxy INTEGER,
  is_blacklisted INTEGER,
  is_anonymous_vpn INTEGER,
  user_type TEXT,
  success_count INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (user_id, host, port, type)
);
CREATE INDEX IF NOT EXISTS idx_proxies_user_status ON proxies(user_id, status);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','running','done','cancelled','failed')),
  total INTEGER NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  alive INTEGER NOT NULL DEFAULT 0,
  dead INTEGER NOT NULL DEFAULT 0,
  timeout_s INTEGER NOT NULL DEFAULT 12,
  retries INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS job_items (
  id INTEGER PRIMARY KEY,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','done')),
  attempts INTEGER NOT NULL DEFAULT 0,
  lease_until TEXT
);
CREATE INDEX IF NOT EXISTS idx_items_claim ON job_items(status, lease_until);

CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY,
  proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
  job_id INTEGER,
  checked_at TEXT NOT NULL,
  alive INTEGER NOT NULL,
  latency_ms INTEGER,
  error TEXT,
  exit_ip TEXT,
  provider TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_proxy ON checks(proxy_id, checked_at);

CREATE TABLE IF NOT EXISTS quota (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
