-- D1 SCHEMA FOR SOCIALSYNC

-- Drop tables if they exist to start fresh (useful for development)
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS allowed_users;

-- Stores the connected Facebook Pages and Instagram Business Accounts
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  owner_name TEXT,
  fb_page_id TEXT NOT NULL,
  fb_page_name TEXT NOT NULL,
  ig_user_id TEXT,
  ig_username TEXT,
  access_token TEXT NOT NULL, -- This will be encrypted
  token_expires_at INTEGER,
  status TEXT NOT NULL DEFAULT 'active', -- 'active', 'error' (e.g., token expired)
  created_at INTEGER,
  updated_at INTEGER,
  last_updated INTEGER -- Generic timestamp for any update
);

-- Stores each "campaign" or post to be sent out
CREATE TABLE posts (
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

-- Logs the result of each individual post to a specific account
CREATE TABLE logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  final_caption TEXT,
  meta_post_id TEXT, -- The ID returned from the FB/IG API
  status TEXT NOT NULL, -- 'success', 'failed'
  error_message TEXT,
  timestamp INTEGER
);

-- Users who are allowed to access/use the application
CREATE TABLE allowed_users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    created_at INTEGER
);

-- INDEXES for performance
CREATE INDEX idx_logs_post_id ON logs(post_id);
CREATE INDEX idx_accounts_status ON accounts(status);
CREATE INDEX idx_posts_status ON posts(status);
CREATE INDEX idx_allowed_users_username ON allowed_users(username);
