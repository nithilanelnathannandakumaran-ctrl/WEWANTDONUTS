CREATE TABLE IF NOT EXISTS signatures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  comment TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
