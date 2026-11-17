<?php
/* ===== SETTINGS: edit these before uploading ===== */
const ADMIN_USER     = 'admin';
const ADMIN_PASSWORD = 'emberence69';   // use a long, unique password
const TIMEZONE       = 'Asia/Kolkata';
const DB_FILE        = __DIR__ . '/../data/quotes-6938d3b64bb9d35b.sqlite';   // random name: do not change after you start collecting requests
const SITE_URL       = '';   // optional: your live address, e.g. 'https://yourdomain.com' (no trailing slash). Empty = detect automatically
const REVIEW_LINK_DAYS = 30; // how long an unused review link stays valid
/* ================================================= */

date_default_timezone_set(TIMEZONE);

/* Trim to a maximum number of characters (UTF-8 safe, works even if the mbstring extension is missing) */
function cap_text(string $v, int $max): string {
    preg_match('/^.{0,' . $max . '}/su', trim($v), $m);
    return $m[0] ?? '';
}

/* Number of characters (not bytes) */
function char_len(string $v): int {
    return (int) preg_match_all('/./su', $v);
}

/* 48-character random token for review links */
function new_token(): string {
    return bin2hex(random_bytes(24));
}

/* Opens (and on first run creates) the database */
function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $dir = dirname(DB_FILE);
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $pdo = new PDO('sqlite:' . DB_FILE, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS quotes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, address TEXT,
  details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New',
  ip TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS review_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  client_name TEXT NOT NULL, handle TEXT, quote_id INTEGER,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL UNIQUE,
  display_name TEXT NOT NULL, rating INTEGER NOT NULL,
  title TEXT, body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'published',
  owner_reply TEXT, edited_by_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS token_attempts (ip TEXT NOT NULL, created_at TEXT NOT NULL);
SQL);
    return $pdo;
}
