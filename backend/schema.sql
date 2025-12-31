-- D1 SCHEMA FOR SOCIALSYNC
-- Safe version: will NOT delete data. Creates tables only if missing.

-- Stores the connected Facebook Pages and Instagram Business Accounts
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  owner_name TEXT,
  fb_page_id TEXT NOT NULL,
  fb_page_name TEXT NOT NULL,
  ig_user_id TEXT,
  ig_username TEXT,
  access_token TEXT NOT NULL, -- encrypted
  token_expires_at INTEGER,
  status TEXT NOT NULL DEFAULT 'active', -- 'active', 'error'
  created_at INTEGER,
  updated_at INTEGER,
  last_updated INTEGER
);

-- Stores each "campaign" or scheduled post
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  public_image_url TEXT NOT NULL,
  base_caption TEXT NOT NULL,
  status TEXT NOT NULL, -- 'pending', 'in_progress', 'completed'
  created_at INTEGER,
  completed_at INTEGER,
  success_count INTEGER DEFAULT 0,
  failure_count INTEGER DEFAULT 0,
  total_accounts INTEGER DEFAULT 0
);

-- Logs the result of each post to each account
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  final_caption TEXT,
  meta_post_id TEXT,
  status TEXT NOT NULL, -- 'success', 'failed'
  error_message TEXT,
  timestamp INTEGER
);

-- Allowed users list
CREATE TABLE IF NOT EXISTS allowed_users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  created_at INTEGER
);

-- Admin users for authentication
CREATE TABLE IF NOT EXISTS admin_users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_active INTEGER DEFAULT 1,
  created_at INTEGER,
  last_login INTEGER
);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_logs_post_id ON logs(post_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status);
CREATE INDEX IF NOT EXISTS idx_allowed_users_username ON allowed_users(username);
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);