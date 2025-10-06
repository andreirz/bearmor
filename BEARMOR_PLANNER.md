# 🛡️ Bearmor Security Plugin — Development Planner

**Mission:** Lightweight, robust WordPress security plugin for SMBs  
**Architecture:** Free tier (essentials) + Paid tier (advanced checks, AI, PDF reports)  
**Pro Unlock:** Call-home license verification with grace period

---

## 📊 Progress Overview

- **Phase 1 (Free Tier):** ⬜ Not Started
- **Phase 2 (Paid Tier):** ⬜ Not Started  
- **Phase 3 (Call-Home/Pro):** ⬜ Not Started

**Legend:** ⬜ Not Started | 🔄 In Progress | ✅ Complete | ⚠️ Blocked | 🧪 Testing

---

## Part 1 — Free Tier (Core Security)

### 1A — Plugin Skeleton & Admin Setup ✅
**Status:** Complete  
**Priority:** Critical  
**Dependencies:** None

**Tasks:**
- [x] Create plugin structure: `bearmor-security/`
  - [x] Main file: `bearmor-security.php` (plugin header, activation/deactivation hooks)
  - [x] Directories: `includes/`, `admin/`, `assets/css/`, `assets/js/`
- [x] Register admin menu: Settings → Bearmor Security → Dashboard
- [x] Capability checks: `manage_options` only
- [x] Initialize WP options: `bearmor_settings`, `bearmor_site_id`
- [x] Global settings page:
  - [x] Scan schedule (daily/weekly/manual)
  - [x] Notification preferences (dashboard-only/email)
  - [x] Opt-in toggles: auto-disable vulnerable plugins, auto-quarantine
- [x] Action buttons: [Save & Apply], [Apply Recommended Hardening]

**Files to Create:**
```
bearmor-security/
├── bearmor-security.php          (main plugin file)
├── includes/
│   ├── class-bearmor-core.php    (core initialization)
│   ├── class-bearmor-settings.php (settings management)
│   └── class-bearmor-helpers.php  (utility functions)
├── admin/
│   ├── class-bearmor-admin.php    (admin interface)
│   ├── dashboard.php              (dashboard view)
│   └── settings.php               (settings view)
└── assets/
    ├── css/admin-style.css
    └── js/admin-script.js
```

**Testing:**
- [x] Plugin activates without errors
- [x] Admin menu appears for admin users only
- [x] Settings save and persist correctly
- [ ] Uninstall cleans up options (deferred)

---

### 1B — Dashboard ✅
**Status:** Complete  
**Priority:** High  
**Dependencies:** 1A

**Tasks:**
- [x] Create one-page dashboard overview with widgets:
  - [x] Security score (0-100) based on active protections
  - [x] Last scan timestamp + status
  - [x] File changes count (link to details)
  - [x] Login events summary (failed/successful)
  - [x] Login anomalies count
  - [x] Firewall blocks count
  - [x] AI summary widget (🔒 Paid - show upgrade prompt for free users)
  - [x] Uptime widget (🔒 Paid - show upgrade prompt for free users)
- [x] Quick action buttons:
  - [x] [View Details] for each widget
  - [x] Action buttons moved to detail pages (better UX)
- [x] Visual indicators: color-coded alerts (green/yellow/red)
- [x] Free vs Paid feature visibility (show locked features with upgrade CTA)

**Files to Create:**
```
admin/
├── dashboard.php
└── partials/
    ├── widget-security-score.php
    ├── widget-file-changes.php
    ├── widget-login-events.php
    ├── widget-anomalies.php
    ├── widget-firewall.php
    ├── widget-ai-summary.php (paid)
    └── widget-uptime.php (paid)
```

**Testing:**
- [x] Dashboard loads without errors
- [x] Widgets display correct data
- [x] Action buttons moved to detail pages
- [x] Paid features show upgrade prompts for free users

---

### 1C — File Change Monitor (Checksums) ✅
**Status:** COMPLETE  
**Priority:** High  
**Dependencies:** 1A

**Tasks:**
- [x] Create checksum scanner for WP core, plugins, themes
- [x] Exclude: `wp-content/uploads/`, `wp-content/cache/`, `*.log`, `.txt`, `.md`, images, videos
- [x] Store baseline checksums: Optimized with serialized arrays (options table) + DB
- [x] Scan functionality:
  - [x] WP Core: Compare against WordPress.org API (official checksums)
  - [x] Plugins/Themes: Compare against baseline (auto-created on activation/update)
  - [x] wp-config.php & mu-plugins: Baseline monitoring
  - [x] Detect modified files (sha1 hashing for speed)
  - [x] Log changes with timestamp
- [x] Admin UI: File Changes page
  - [x] List changed files with: path, size, belongs to, last checked, status
  - [x] Actions per file: [Quarantine], [Mark Safe], [Restore]
  - [x] File preview: AJAX-based, on-demand loading (< 100 lines: show all, > 100 lines: first 50 + last 50)
  - [x] Smart quarantine: Auto-deactivates plugins/themes before quarantine
  - [x] Mark Safe: Updates baseline to prevent re-flagging
- [x] Safety modes:
  - [x] Default: flag only (alert, no auto-action)
  - [x] Safe Mode: Smart deactivation prevents site breakage
- [x] Auto-baseline creation:
  - [x] On plugin activation (first time only)
  - [x] On plugin/theme update (rebuilds baseline, clears old changes)
- [ ] WP-CLI command: `wp bearmor scan files` (deferred to 2H)

**Files to Create:**
```
includes/
├── class-bearmor-file-scanner.php
├── class-bearmor-checksum.php
└── class-bearmor-file-actions.php
admin/
└── file-changes.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_file_checksums (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  file_path VARCHAR(500) NOT NULL,
  checksum VARCHAR(64) NOT NULL,
  file_size BIGINT UNSIGNED,
  last_checked DATETIME NOT NULL,
  status ENUM('baseline', 'changed', 'new', 'deleted', 'safe') DEFAULT 'baseline',
  UNIQUE KEY file_path (file_path)
);

CREATE TABLE bearmor_file_changes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  file_path VARCHAR(500) NOT NULL,
  old_checksum VARCHAR(64),
  new_checksum VARCHAR(64),
  detected_at DATETIME NOT NULL,
  action_taken ENUM('none', 'locked', 'quarantined', 'marked_safe') DEFAULT 'none',
  action_by BIGINT UNSIGNED,
  INDEX detected_at (detected_at)
);
```

**Testing:**
- [ ] Baseline scan completes successfully
- [ ] Modified file detected correctly
- [ ] Lock file works (rename in Safe Mode)
- [ ] Quarantine moves file correctly
- [ ] Restore from quarantine works
- [ ] Mark Safe ignores file in future scans

---

### 1D — Regex Malware Scan ✅
**Status:** ✅ COMPLETED  
**Priority:** High  
**Dependencies:** 1A, 1C

**Tasks:**
- [x] Create regex pattern library for suspicious code:
  - [x] `eval(`, `base64_decode(`, `gzinflate(`, `str_rot13(`
  - [x] Obfuscated variable patterns: `${'GLOBALS'}`, `$$`
  - [x] Shell execution: `exec(`, `system(`, `passthru(`, `shell_exec(`
  - [x] File operations: `file_put_contents(` with dynamic content
  - [x] Network operations: `curl_exec()`, `fsockopen()`, `file_get_contents(http)`
  - [x] Encoded payloads: long base64 strings (200+ chars)
  - [x] Combined patterns: `eval(base64_decode())`, `assert(base64_decode())`
- [x] Scan PHP, JS, HTML files in core/plugins/themes
- [x] Strip PHP comments to avoid false positives
- [x] Map line numbers from stripped to original content
- [x] Exclude WordPress core files (whitelist)
- [x] Admin UI: Malware Alerts page
  - [x] List suspicious files grouped by file with: path, pattern, severity, timestamp
  - [x] Show code preview with 10 lines before/after, highlighted threat line
  - [x] Actions: [Quarantine File], [Whitelist File]
  - [x] Tooltips with pattern descriptions
  - [x] Threat summary cards (Critical/High/Medium/Low counts)
  - [x] Quarantined files table with restore functionality
- [x] False positive handling: whitelist files permanently
- [x] Severity scoring: critical/high/medium/low with color coding
- [x] Dashboard widget: Last Scan with threat counts by severity

**Files to Create:**
```
includes/
├── class-bearmor-malware-scanner.php
├── class-bearmor-regex-patterns.php
└── class-bearmor-false-positives.php
admin/
└── malware-alerts.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_malware_detections (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  file_path VARCHAR(500) NOT NULL,
  pattern_matched VARCHAR(255) NOT NULL,
  severity ENUM('critical', 'high', 'medium', 'low') DEFAULT 'medium',
  code_snippet TEXT,
  line_number INT,
  detected_at DATETIME NOT NULL,
  status ENUM('new', 'marked_safe', 'locked', 'quarantined') DEFAULT 'new',
  action_by BIGINT UNSIGNED,
  INDEX detected_at (detected_at),
  INDEX status (status)
);
```

**Testing:**
- [ ] Scan detects known malware patterns
- [ ] False positives can be marked safe
- [ ] Severity scoring works correctly
- [ ] Lock/quarantine actions work
- [ ] Whitelist prevents repeated alerts

---

### 1E — Brute-Force Lockout ✅
**Status:** ✅ COMPLETED (needs live testing for email/country)
**Priority:** High  
**Dependencies:** 1A

**Tasks:**
- [x] Hook into login system to track login attempts
- [x] Rate limiting per IP:
  - [x] 5 failed attempts → 5 min lockout
  - [x] 10 failed attempts → 30 min lockout
  - [x] 20 failed attempts → 24 hour lockout
  - [x] Progressive lockout algorithm (accumulates in 1 hour window)
- [x] Store attempts in database (better than transients)
- [x] Admin UI: Login Activity page
  - [x] Single-page view (no tabs - better UX)
  - [x] Combined failed & successful logins table
  - [x] Display: IP, username, timestamp, status, user agent
  - [x] Actions: [Block IP Permanently], [Unblock IP], [Whitelist IP]
  - [x] Blocked & Whitelisted IPs section at top
- [x] Whitelist functionality: never block whitelisted IPs
- [x] Auto-cleanup: Keep last 1000 login attempts, remove expired blocks
- [x] Clear failed attempts on unblock/block expiry
- [ ] **Country detection (NEEDS LIVE TESTING)** - ip-api.com integration added
- [ ] **Email notification (NEEDS LIVE TESTING)** - sends on 24h ban only

**Files to Create:**
```
includes/
├── class-bearmor-login-protection.php
├── class-bearmor-ip-manager.php
└── class-bearmor-rate-limiter.php
admin/
└── login-activity.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_login_attempts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL,
  username VARCHAR(60),
  success TINYINT(1) DEFAULT 0,
  attempted_at DATETIME NOT NULL,
  user_agent TEXT,
  country_code VARCHAR(2),
  INDEX ip_address (ip_address),
  INDEX attempted_at (attempted_at)
);

CREATE TABLE bearmor_blocked_ips (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL UNIQUE,
  blocked_at DATETIME NOT NULL,
  expires_at DATETIME,
  reason VARCHAR(255),
  permanent TINYINT(1) DEFAULT 0
);
```

**Testing:**
- [x] Failed login tracked correctly
- [x] IP blocked after threshold (5/10/20 attempts)
- [x] Progressive lockout works (5min/30min/24h)
- [x] Unblock IP works and clears counter
- [x] Whitelist prevents blocking
- [ ] **Country detection works on live server** (can't test on local)
- [ ] **Email notification received on 24h ban** (can't test on local)

---

### 1F — Login Anomaly Detection 🔄
**Status:** Partially Complete (needs live server testing)
**Priority:** Medium  
**Dependencies:** 1E

**Tasks:**
- [x] Track user login patterns:
  - [x] Usual IP addresses
  - [x] Usual countries/locations (code ready, needs live testing)
  - [x] Usual devices/user agents (tested ✅)
  - [x] Usual login times
- [ ] Detect anomalies:
  - [ ] **Impossible travel:** Login from different countries within short time (code ready, needs live testing)
  - [ ] **TOR/VPN detection:** Known TOR exit nodes, datacenter IPs (NOT IMPLEMENTED)
  - [ ] **First-time country:** Login from never-before-seen country (code ready, needs live testing)
  - [x] **New device:** Unknown user agent (tested ✅ - Opera detected as different from Chrome)
  - [x] **Unusual time:** Login at 3 AM when user typically logs in at 9 AM (code ready, needs testing)
- [x] Scoring system: anomaly score 0-100 (tested ✅)
- [x] Dashboard alert widget for critical anomalies (score > 80) (tested ✅)
- [x] Admin UI: Login Anomalies page
  - [x] List anomalies with: user, IP, country, device, anomaly type, score, timestamp (tested ✅)
  - [x] Actions: [Mark Safe], [Block IP] (tested ✅)
  - [ ] Actions: [Force Password Reset] (NOT IMPLEMENTED)
- [x] Email notification for critical anomalies (code ready, needs live testing)

**Files Created:**
```
includes/
├── class-bearmor-anomaly-detector.php ✅ (created, includes user profile tracking)
admin/
└── login-anomalies.php ✅ (created)
admin/partials/
└── widget-anomalies.php ✅ (updated with real data)
```

**Notes:**
- GeoIP integrated into existing login-protection class (uses ip-api.com)
- User profile tracking integrated into anomaly-detector class
- Browser detection improved: Opera, Edge, Vivaldi, Brave all detected separately from Chrome

**Database Schema:**
```sql
CREATE TABLE bearmor_login_anomalies (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  country_code VARCHAR(2),
  anomaly_type ENUM('impossible_travel', 'tor_vpn', 'new_country', 'new_device', 'unusual_time') NOT NULL,
  anomaly_score INT NOT NULL,
  detected_at DATETIME NOT NULL,
  status ENUM('new', 'marked_safe', 'blocked') DEFAULT 'new',
  action_by BIGINT UNSIGNED,
  INDEX user_id (user_id),
  INDEX detected_at (detected_at),
  INDEX anomaly_score (anomaly_score)
);

CREATE TABLE bearmor_user_profiles (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL UNIQUE,
  known_ips TEXT,
  known_countries TEXT,
  known_user_agents TEXT,
  typical_login_hours VARCHAR(255),
  profile_created DATETIME NOT NULL,
  profile_updated DATETIME NOT NULL
);
```

**Testing:**
- [x] Normal login builds user profile (tested ✅)
- [ ] Impossible travel detected (needs live server with VPN)
- [ ] TOR node detected (NOT IMPLEMENTED)
- [ ] New country flagged (needs live server with VPN)
- [x] New device detected (tested ✅ - Opera vs Chrome)
- [x] Anomaly logged to database (tested ✅)
- [x] Anomaly displayed on admin page (tested ✅)
- [x] Mark Safe action works (tested ✅)
- [x] Block IP action works (tested ✅)
- [x] Dashboard widget shows anomalies (tested ✅)
- [ ] Email sent for critical anomalies (needs live server)

---

### 1G — Hardening & Security Headers ⬜
**Status:** Not Started  
**Priority:** High  
**Dependencies:** 1A

**Tasks:**
- [ ] Security headers (via `send_headers` hook):
  - [ ] `X-Frame-Options: SAMEORIGIN`
  - [ ] `X-Content-Type-Options: nosniff`
  - [ ] `Referrer-Policy: strict-origin-when-cross-origin`
  - [ ] `Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - [ ] `X-XSS-Protection: 1; mode=block`
- [ ] Hardening options:
  - [ ] Force SSL (redirect HTTP → HTTPS)
  - [ ] Disable file editing: `DISALLOW_FILE_EDIT`
  - [ ] Disable WP_DEBUG in production
  - [ ] Hide WP version (remove generator tags)
  - [ ] Block user enumeration (`?author=` queries)
  - [ ] Disable verbose login errors
  - [ ] Disable XML-RPC (if not needed)
- [ ] Admin UI: Hardening page
  - [ ] Show pass/fail status for each hardening measure
  - [ ] Toggle switches to enable/disable each
  - [ ] [Apply Recommended Hardening] button (one-click)
  - [ ] [Revert All] button
- [ ] `.htaccess` modifications (with backup)

**Files to Create:**
```
includes/
├── class-bearmor-hardening.php
├── class-bearmor-headers.php
└── class-bearmor-htaccess.php
admin/
└── hardening.php
```

**Testing:**
- [ ] Security headers present in response
- [ ] SSL redirect works
- [ ] File editing disabled in admin
- [ ] WP version hidden
- [ ] User enumeration blocked
- [ ] XML-RPC disabled (if toggled)
- [ ] .htaccess backup created before modification

---

### 1H — Lock / Manual Quarantine ⬜
**Status:** Not Started  
**Priority:** High  
**Dependencies:** 1C, 1D

**Tasks:**
- [ ] **Lock File:**
  - [ ] Default mode: `chmod 000` (make unreadable)
  - [ ] Safe Mode: rename file to `.locked` extension
  - [ ] Store original permissions in DB
- [ ] **Quarantine:**
  - [ ] Create quarantine directory: `wp-content/bearmor-quarantine/`
  - [ ] Move file to quarantine with timestamp
  - [ ] Store original path in DB
  - [ ] Protect quarantine directory (deny web access via .htaccess)
- [ ] **Restore:**
  - [ ] Restore from lock: revert permissions or rename back
  - [ ] Restore from quarantine: move file back to original location
  - [ ] Verify file integrity after restore
- [ ] Admin UI: Quarantine page
  - [ ] List quarantined files with: original path, quarantined date, reason
  - [ ] Actions: [Restore], [Delete Permanently], [Download]
  - [ ] Restore history log
- [ ] Audit log: track all lock/quarantine/restore actions

**Files to Create:**
```
includes/
├── class-bearmor-file-actions.php (extend from 1C)
├── class-bearmor-quarantine.php
└── class-bearmor-audit-log.php
admin/
└── quarantine.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_quarantine (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  file_path VARCHAR(500) NOT NULL,
  quarantined_path VARCHAR(500) NOT NULL,
  reason VARCHAR(255),
  quarantined_at DATETIME NOT NULL,
  quarantined_by BIGINT UNSIGNED,
  restored_at DATETIME,
  restored_by BIGINT UNSIGNED,
  status ENUM('quarantined', 'restored', 'deleted') DEFAULT 'quarantined',
  INDEX status (status)
);

CREATE TABLE bearmor_audit_log (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  action_type ENUM('lock', 'unlock', 'quarantine', 'restore', 'delete', 'mark_safe', 'disable_plugin', 'enable_plugin') NOT NULL,
  target_type ENUM('file', 'plugin', 'setting') NOT NULL,
  target_path VARCHAR(500),
  performed_by BIGINT UNSIGNED,
  performed_at DATETIME NOT NULL,
  details TEXT,
  INDEX performed_at (performed_at),
  INDEX action_type (action_type)
);
```

**Testing:**
- [ ] Lock file works (both modes)
- [ ] Quarantine moves file correctly
- [ ] Quarantine directory protected from web access
- [ ] Restore from lock works
- [ ] Restore from quarantine works
- [ ] Audit log records all actions
- [ ] Delete permanently removes file

---

### 1I — Notifications ⬜
**Status:** Not Started  
**Priority:** Medium  
**Dependencies:** 1A, 1C, 1D, 1E, 1F

**Tasks:**
- [ ] Notification system:
  - [ ] Dashboard notifications (always on)
  - [ ] Email notifications (opt-in)
  - [ ] Notification types: info, warning, critical
- [ ] Trigger notifications for:
  - [ ] Malware detected (critical)
  - [ ] File tampering (warning)
  - [ ] Repeated brute-force attempts (warning)
  - [ ] Login anomaly (critical)
  - [ ] Vulnerable plugin detected (warning) — Paid
  - [ ] License check failed (warning) — Paid
  - [ ] Uptime downtime (critical) — Paid
- [ ] Admin UI: Notifications page
  - [ ] List all notifications with: type, message, timestamp, status
  - [ ] Actions: [Mark Read], [Dismiss], [Clear All]
  - [ ] Filter by type and date
- [ ] Email template: branded, clear, actionable
- [ ] Rate limiting: don't spam emails (max 1 per hour per type)

**Files to Create:**
```
includes/
├── class-bearmor-notifications.php
├── class-bearmor-email.php
└── templates/
    └── email-notification.php
admin/
└── notifications.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_notifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  notification_type ENUM('info', 'warning', 'critical') NOT NULL,
  title VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  related_type ENUM('file', 'plugin', 'login', 'license', 'uptime'),
  related_id BIGINT UNSIGNED,
  created_at DATETIME NOT NULL,
  read_at DATETIME,
  dismissed_at DATETIME,
  email_sent TINYINT(1) DEFAULT 0,
  INDEX created_at (created_at),
  INDEX notification_type (notification_type)
);
```

**Testing:**
- [ ] Dashboard notification appears
- [ ] Email sent (if enabled)
- [ ] Rate limiting prevents spam
- [ ] Mark read/dismiss works
- [ ] Notifications filtered correctly

---

### 1J — 2FA (Simple, Free Tier) ⬜
**Status:** Not Started  
**Priority:** Low  
**Dependencies:** 1A

**Tasks:**
- [ ] Email-based one-time code (6 digits)
- [ ] Hook into login flow: after password validation
- [ ] Generate code, store in transient (5 min expiry)
- [ ] Send code via email
- [ ] Verification page: enter code
- [ ] Admin UI: 2FA Settings
  - [ ] Toggle: Enable/Disable 2FA
  - [ ] Per-user setting (user profile page)
  - [ ] Backup codes (generate 10 codes for emergency access)
- [ ] Remember device option (30 days cookie)

**Files to Create:**
```
includes/
├── class-bearmor-2fa.php
└── class-bearmor-2fa-email.php
admin/
└── 2fa-settings.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_2fa_codes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  code VARCHAR(6) NOT NULL,
  created_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  used TINYINT(1) DEFAULT 0,
  INDEX user_id (user_id),
  INDEX expires_at (expires_at)
);

CREATE TABLE bearmor_2fa_backup_codes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  code VARCHAR(20) NOT NULL,
  used TINYINT(1) DEFAULT 0,
  INDEX user_id (user_id)
);
```

**Testing:**
- [ ] 2FA code sent via email
- [ ] Code verification works
- [ ] Code expires after 5 min
- [ ] Backup codes work
- [ ] Remember device works (30 days)
- [ ] 2FA can be disabled per user

---

### 1K — Admin Action Logging ⬜
**Status:** Not Started  
**Priority:** Low  
**Dependencies:** 1H

**Tasks:**
- [ ] Extend audit log from 1H
- [ ] Track all manual/admin actions:
  - [ ] Lock/unlock file
  - [ ] Quarantine/restore file
  - [ ] Mark safe (malware/anomaly)
  - [ ] Disable/enable plugin
  - [ ] Block/unblock IP
  - [ ] Apply hardening
  - [ ] Change settings
- [ ] Admin UI: Audit Log page
  - [ ] List all actions with: action, target, user, timestamp, details
  - [ ] Filter by action type, user, date range
  - [ ] Export to CSV
- [ ] Retention policy: keep logs for 90 days (configurable)

**Files to Create:**
```
admin/
└── audit-log.php
```

**Testing:**
- [ ] All actions logged correctly
- [ ] Filter works
- [ ] Export to CSV works
- [ ] Retention policy deletes old logs

---

## Part 2 — Paid Tier (Advanced Features)

### 2A — WPVulnerability Integration ⬜
**Status:** Not Started  
**Priority:** High  
**Dependencies:** 1A, 3A (call-home for Pro check)

**Tasks:**
- [ ] Integrate WPVulnerability API (or WPScan API)
- [ ] Scan active plugins, themes, WP core
- [ ] API request: send slug + version
- [ ] Cache results for 24 hours (transient)
- [ ] Admin UI: Vulnerabilities page
  - [ ] List vulnerabilities with: plugin/theme name, version, severity, CVE, description, fix
  - [ ] Actions: [Update Now], [Disable Now], [Whitelist], [View Details]
  - [ ] Filter by severity: critical/high/medium/low
- [ ] Dashboard widget: vulnerability count + top critical
- [ ] Email notification for critical vulnerabilities (opt-in)

**Files to Create:**
```
includes/
├── class-bearmor-vulnerability-scanner.php
└── class-bearmor-wpvulnerability-api.php
admin/
└── vulnerabilities.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_vulnerabilities (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  plugin_slug VARCHAR(255) NOT NULL,
  plugin_version VARCHAR(50) NOT NULL,
  vulnerability_type ENUM('plugin', 'theme', 'core') DEFAULT 'plugin',
  severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
  cve VARCHAR(50),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  fixed_in VARCHAR(50),
  detected_at DATETIME NOT NULL,
  status ENUM('active', 'whitelisted', 'fixed', 'disabled') DEFAULT 'active',
  INDEX plugin_slug (plugin_slug),
  INDEX severity (severity)
);
```

**Testing:**
- [ ] API request successful
- [ ] Vulnerabilities detected correctly
- [ ] Cache works (24h)
- [ ] Update/disable actions work
- [ ] Whitelist prevents repeated alerts
- [ ] Email sent for critical vulns

---

### 2B — Auto-Disable Vulnerable Plugins (Opt-In) ⬜
**Status:** Not Started  
**Priority:** Medium  
**Dependencies:** 2A

**Tasks:**
- [ ] **Default: OFF** (admin must explicitly enable)
- [ ] Before disabling:
  - [ ] Create snapshot: copy plugin folder to backup location
  - [ ] Export plugin settings from DB (if any)
  - [ ] Store in `bearmor_plugin_snapshots` table
- [ ] Disable plugin via `deactivate_plugins()`
- [ ] Notify admin:
  - [ ] Dashboard notification (critical)
  - [ ] Email notification
  - [ ] Include: plugin name, vulnerability, restore button
- [ ] Admin UI: Disabled Plugins page
  - [ ] List disabled plugins with: name, reason, disabled date, snapshot available
  - [ ] Actions: [Restore], [Delete Snapshot], [Keep Disabled]
- [ ] Auto-restore if plugin updated to fixed version

**Files to Create:**
```
includes/
├── class-bearmor-auto-disable.php
└── class-bearmor-plugin-snapshot.php
admin/
└── disabled-plugins.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_plugin_snapshots (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  plugin_slug VARCHAR(255) NOT NULL,
  plugin_version VARCHAR(50) NOT NULL,
  snapshot_path VARCHAR(500) NOT NULL,
  settings_backup TEXT,
  disabled_at DATETIME NOT NULL,
  disabled_reason VARCHAR(255),
  restored_at DATETIME,
  status ENUM('disabled', 'restored', 'deleted') DEFAULT 'disabled',
  INDEX plugin_slug (plugin_slug)
);
```

**Testing:**
- [ ] Snapshot created before disable
- [ ] Plugin disabled successfully
- [ ] Notification sent
- [ ] Restore works (plugin + settings)
- [ ] Auto-restore on update works

---

### 2C — Firewall Lite (Enhanced) ⬜
**Status:** Not Started  
**Priority:** High  
**Dependencies:** 1A, 3A (call-home for Pro features)

**Tasks:**
- [ ] **Free tier:** Basic SQLi/XSS blocking
- [ ] **Paid tier:** Advanced rules
  - [ ] Country blocking (GeoIP)
  - [ ] Bad user-agent blocking (bots, scrapers)
  - [ ] Honeypot fields for forms
  - [ ] Rate limiting per IP (requests/min)
- [ ] Hook into `init` (early execution)
- [ ] Check request for malicious patterns:
  - [ ] SQL injection: `UNION SELECT`, `' OR '1'='1`, etc.
  - [ ] XSS: `<script>`, `javascript:`, `onerror=`, etc.
  - [ ] Path traversal: `../`, `..\\`
  - [ ] Command injection: `; rm -rf`, `| cat /etc/passwd`
- [ ] Block request: return 403 Forbidden
- [ ] Log blocked requests
- [ ] Admin UI: Firewall page
  - [ ] Toggle rules on/off
  - [ ] Whitelist IPs/URIs
  - [ ] View blocked requests log
  - [ ] Country blocking settings (Paid)
  - [ ] User-agent blacklist (Paid)

**Files to Create:**
```
includes/
├── class-bearmor-firewall.php
├── class-bearmor-firewall-rules.php
└── class-bearmor-geolocation.php (extend from 1F)
admin/
└── firewall.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_firewall_blocks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL,
  request_uri TEXT NOT NULL,
  request_method VARCHAR(10),
  user_agent TEXT,
  rule_matched VARCHAR(255),
  blocked_at DATETIME NOT NULL,
  INDEX ip_address (ip_address),
  INDEX blocked_at (blocked_at)
);

CREATE TABLE bearmor_firewall_whitelist (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  whitelist_type ENUM('ip', 'uri') NOT NULL,
  value VARCHAR(500) NOT NULL,
  added_at DATETIME NOT NULL
);
```

**Testing:**
- [ ] SQLi request blocked
- [ ] XSS request blocked
- [ ] Path traversal blocked
- [ ] Whitelist IP bypasses firewall
- [ ] Country blocking works (Paid)
- [ ] User-agent blocking works (Paid)
- [ ] Logs display correctly

---

### 2D — Deeper Scans (DB + Uploads) ⬜
**Status:** Not Started  
**Priority:** Medium  
**Dependencies:** 1D, 3A

**Tasks:**
- [ ] **Database scan:**
  - [ ] Scan `wp_posts` (post_content, post_excerpt) for suspicious scripts
  - [ ] Scan `wp_options` (option_value) for injected code
  - [ ] Scan `wp_comments` (comment_content) for malicious links
  - [ ] Detect: `<script>`, `<iframe>`, obfuscated JS, known malware URLs
- [ ] **Uploads scan:**
  - [ ] Scan `wp-content/uploads/` for PHP files (shouldn't be there)
  - [ ] Scan image files for embedded PHP code (polyglot files)
  - [ ] Detect suspicious file extensions: `.php.jpg`, `.phtml`, etc.
- [ ] Admin UI: Deep Scan Results page
  - [ ] Tabs: Database | Uploads
  - [ ] List suspicious items with: location, matched pattern, severity
  - [ ] Actions: [View], [Mark Safe], [Remove], [Quarantine]
- [ ] Performance: batch processing for large sites

**Files to Create:**
```
includes/
├── class-bearmor-db-scanner.php
├── class-bearmor-uploads-scanner.php
└── class-bearmor-batch-processor.php
admin/
└── deep-scan.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_db_detections (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  table_name VARCHAR(64) NOT NULL,
  column_name VARCHAR(64) NOT NULL,
  row_id BIGINT UNSIGNED NOT NULL,
  pattern_matched VARCHAR(255) NOT NULL,
  severity ENUM('critical', 'high', 'medium', 'low') DEFAULT 'medium',
  detected_at DATETIME NOT NULL,
  status ENUM('new', 'marked_safe', 'removed') DEFAULT 'new',
  INDEX detected_at (detected_at)
);
```

**Testing:**
- [ ] DB scan detects injected scripts
- [ ] Uploads scan detects PHP files
- [ ] Polyglot file detected
- [ ] Mark safe works
- [ ] Remove from DB works
- [ ] Batch processing handles large sites

---

### 2E — AI Analysis (OpenAI Integration) ⬜
**Status:** Not Started  
**Priority:** Medium  
**Dependencies:** 1C, 1D, 1E, 1F, 2A, 3A

**Tasks:**
- [ ] Generate sanitized log summary (≤1 A4 page):
  - [ ] File changes: count, top 5 files
  - [ ] Malware detections: count, top 3 patterns
  - [ ] Login anomalies: count, top 3 anomalies
  - [ ] Vulnerabilities: count, top 3 critical
  - [ ] Uptime/downtime: percentage, incidents
  - [ ] Firewall blocks: count, top IPs
- [ ] Send summary to OpenAI API:
  - [ ] Prompt: "You are a WordPress security expert. Analyze this security log and provide friendly recommendations."
  - [ ] Model: GPT-4 or GPT-3.5-turbo
  - [ ] Max tokens: 500
- [ ] Parse AI response
- [ ] Admin UI: AI Analysis page
  - [ ] Display AI verdict and recommendations
  - [ ] Show summary data used
  - [ ] [Regenerate Analysis] button
  - [ ] Dashboard widget: AI summary snippet
- [ ] False positive learning:
  - [ ] Track [Mark Safe] actions
  - [ ] Include in future prompts: "Previously marked safe: [list]"
- [ ] Fail-safe: if API unavailable, show "Service unavailable" notice

**Files to Create:**
```
includes/
├── class-bearmor-ai-analysis.php
├── class-bearmor-openai-api.php
└── class-bearmor-log-summarizer.php
admin/
└── ai-analysis.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_ai_analysis (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  summary_data TEXT NOT NULL,
  ai_response TEXT NOT NULL,
  generated_at DATETIME NOT NULL,
  tokens_used INT,
  INDEX generated_at (generated_at)
);
```

**Testing:**
- [ ] Log summary generated correctly
- [ ] OpenAI API request successful
- [ ] AI response parsed and displayed
- [ ] False positive learning works
- [ ] Fail-safe handles API unavailability
- [ ] Dashboard widget displays snippet

---

### 2F — PDF Reports ⬜
**Status:** Not Started  
**Priority:** Low  
**Dependencies:** 2E

**Tasks:**
- [ ] Generate PDF report using library (TCPDF or mPDF)
- [ ] Report contents:
  - [ ] Cover page: site name, date range, Bearmor branding
  - [ ] Executive summary: security score, key findings
  - [ ] Uptime: percentage, downtime incidents
  - [ ] Vulnerabilities: list with severity
  - [ ] File changes: count, critical changes
  - [ ] Malware detections: count, actions taken
  - [ ] Login activity: anomalies, blocked IPs
  - [ ] AI analysis: recommendations
  - [ ] Actions taken: audit log summary
- [ ] Admin UI: Reports page
  - [ ] Date range selector (last 7/30/90 days, custom)
  - [ ] [Generate PDF] button
  - [ ] [Download] link after generation
  - [ ] Report history: list previous reports
- [ ] Optional: scheduled reports (weekly/monthly via WP Cron)
  - [ ] Email PDF as attachment

**Files to Create:**
```
includes/
├── class-bearmor-pdf-generator.php
├── class-bearmor-report-builder.php
└── libraries/tcpdf/ (or mPDF)
admin/
└── reports.php
```

**Database Schema:**
```sql
CREATE TABLE bearmor_reports (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  report_type ENUM('manual', 'scheduled') DEFAULT 'manual',
  date_from DATE NOT NULL,
  date_to DATE NOT NULL,
  file_path VARCHAR(500) NOT NULL,
  generated_at DATETIME NOT NULL,
  generated_by BIGINT UNSIGNED,
  INDEX generated_at (generated_at)
);
```

**Testing:**
- [ ] PDF generated successfully
- [ ] All sections populated correctly
- [ ] Download works
- [ ] Scheduled report sent via email
- [ ] Report history displays correctly

---

### 2G — Uptime Monitoring ⬜
**Status:** Not Started  
**Priority:** Medium  
**Dependencies:** 3A (call-home server)

**Tasks:**
- [ ] **Server-side ping:**
  - [ ] Call-home server pings site URL every 5 minutes
  - [ ] Check HTTP status code (200 = up, else = down)
  - [ ] Measure response time
  - [ ] Store results on server
- [ ] **Plugin receives uptime data:**
  - [ ] Call-home response includes: `uptime_percentage`, `last_downtime`, `avg_response_time`
  - [ ] Cache locally for 24h
- [ ] Dashboard widget: Uptime
  - [ ] Display: uptime % (last 30 days), last downtime, avg response time
  - [ ] Visual: uptime graph (last 7 days)
- [ ] Admin UI: Uptime page
  - [ ] Detailed uptime history (last 90 days)
  - [ ] Downtime incidents: timestamp, duration, status code
  - [ ] Response time graph
- [ ] Email notification for downtime (opt-in)
  - [ ] Alert after 2 consecutive failed pings (10 min down)

**Files to Create:**
```
includes/
├── class-bearmor-uptime.php
└── class-bearmor-uptime-display.php
admin/
└── uptime.php
```

**Server-side (separate project):**
```
bearmor-server/
└── uptime-monitor/
    ├── ping-scheduler.php (cron job)
    └── uptime-api.php (return data to plugin)
```

**Testing:**
- [ ] Server pings site successfully
- [ ] Downtime detected correctly
- [ ] Plugin receives uptime data
- [ ] Dashboard widget displays correctly
- [ ] Uptime page shows history
- [ ] Email sent on downtime

---

### 2H — Performance & Safety Enhancements ⬜
**Status:** Not Started  
**Priority:** Low  
**Dependencies:** 1C, 1D, 2D

**Tasks:**
- [ ] **Batch processing:**
  - [ ] Scan large sites in chunks (100 files per batch)
  - [ ] Pause/resume functionality
  - [ ] Progress bar in admin UI
- [ ] **File exclusion patterns:**
  - [ ] Admin UI: exclude directories/file patterns from scans
  - [ ] Examples: `node_modules/`, `*.min.js`, `vendor/`
- [ ] **Safe-mode file operations:**
  - [ ] Always rename instead of chmod (hosting compatibility)
  - [ ] Verify file exists before restore
  - [ ] Rollback on error
- [ ] **Performance optimizations:**
  - [ ] Use transients for caching
  - [ ] Lazy load admin pages
  - [ ] Optimize DB queries (indexes, limits)
  - [ ] WP-CLI commands for large operations

**Files to Create:**
```
includes/
├── class-bearmor-batch-processor.php (extend from 2D)
└── class-bearmor-performance.php
```

**Testing:**
- [ ] Batch processing works on large site
- [ ] Pause/resume works
- [ ] File exclusion works
- [ ] Safe-mode operations work
- [ ] Performance acceptable on large sites

---

## Part 3 — Call-Home / Pro Unlock

### 3A — Site ID & Registration ⬜
**Status:** Not Started  
**Priority:** Critical  
**Dependencies:** 1A

**Tasks:**
- [ ] Generate unique `site_id` on plugin activation
  - [ ] Use `wp_generate_uuid4()` or `uniqid()`
  - [ ] Store in `wp_options`: `bearmor_site_id`
- [ ] Register site with call-home server:
  - [ ] POST to `https://api.bearmor.com/v1/register`
  - [ ] Payload: `{site_id, url, created_at, plan: "free"}`
  - [ ] Response: `{success, message}`
- [ ] Admin UI: License page
  - [ ] Display site ID (for support)
  - [ ] Display current plan: Free / Paid / Pro
  - [ ] [Request Trial] button (7-day Pro trial)
  - [ ] [Upgrade to Paid] button (link to pricing page)
  - [ ] License status: Active / Expired / Failed to verify

**Files to Create:**
```
includes/
├── class-bearmor-license.php
├── class-bearmor-callhome-api.php
└── class-bearmor-site-registration.php
admin/
└── license.php
```

**Server-side (separate project):**
```
bearmor-server/
└── api/
    ├── register.php
    └── verify.php
```

**Testing:**
- [ ] Site ID generated on activation
- [ ] Registration request successful
- [ ] License page displays correctly
- [ ] Trial request works

---

### 3B — Call-Home Daily ⬜
**Status:** Not Started  
**Priority:** Critical  
**Dependencies:** 3A

**Tasks:**
- [ ] Daily call-home (WP Cron):
  - [ ] POST to `https://api.bearmor.com/v1/verify`
  - [ ] Payload: `{site_id, plugin_version, url, timestamp}`
  - [ ] Response: `{pro_enabled, plan, expires, signature}`
- [ ] Verify signature:
  - [ ] Use public key stored in plugin
  - [ ] Verify HMAC-SHA256 signature
  - [ ] Reject if signature invalid
- [ ] Cache response locally:
  - [ ] Store in transient: `bearmor_license_cache` (24h expiry)
  - [ ] Store: `pro_enabled`, `plan`, `expires`, `last_verified`
- [ ] Unlock Paid features:
  - [ ] Check `pro_enabled` flag before showing Paid features
  - [ ] If `pro_enabled === true`, show all Paid features
  - [ ] If `pro_enabled === false`, show upgrade prompts
- [ ] Admin UI: License page
  - [ ] Display: plan, expires date, last verified
  - [ ] [Verify Now] button (manual check)

**Files to Create:**
```
includes/
├── class-bearmor-callhome.php (extend from 3A)
└── class-bearmor-signature-verify.php
```

**Testing:**
- [ ] Daily call-home successful
- [ ] Signature verified correctly
- [ ] Cache stored for 24h
- [ ] Pro features unlocked when `pro_enabled = true`
- [ ] Manual verify works

---

### 3C — Safety & UX Rules ⬜
**Status:** Not Started  
**Priority:** High  
**Dependencies:** All previous tasks

**Tasks:**
- [ ] **Default behavior: passive (alert-first)**
  - [ ] Never auto-lock/quarantine/disable without admin opt-in
  - [ ] Always show alert first, let admin decide
- [ ] **Auto-actions only when explicitly enabled:**
  - [ ] Settings page: toggle for each auto-action
  - [ ] Examples: auto-quarantine malware, auto-disable vulnerable plugins
  - [ ] Clear warning: "This will automatically take action without confirmation"
- [ ] **Restore options for all destructive actions:**
  - [ ] Lock → Unlock
  - [ ] Quarantine → Restore
  - [ ] Disable plugin → Restore (with snapshot)
  - [ ] All actions logged in audit log
- [ ] **Fail-safe if API/OpenAI unavailable:**
  - [ ] Show "Service unavailable" notice
  - [ ] Never auto-disable features
  - [ ] Cache last known good state
- [ ] **Grace period logic:**
  - [ ] Day 1–2 fail: silent cache, no alerts
  - [ ] Day 3–4 fail: dashboard notice "License check failed, please retry"
  - [ ] Day 7+ fail: disable Pro features, Free tier keeps working
  - [ ] Admin can manually verify anytime
- [ ] Admin UI: Safety Settings page
  - [ ] Toggle: Enable auto-actions
  - [ ] Toggle: Enable grace period (default ON)
  - [ ] Grace period duration: 3/7/14 days

**Files to Create:**
```
includes/
├── class-bearmor-safety.php
└── class-bearmor-grace-period.php
admin/
└── safety-settings.php
```

**Testing:**
- [ ] Default behavior is passive
- [ ] Auto-actions only work when enabled
- [ ] Restore works for all actions
- [ ] Fail-safe handles API unavailability
- [ ] Grace period works correctly
- [ ] Day 3–4: notice appears
- [ ] Day 7+: Pro features disabled, Free works

---

### 3D — Testing Checklist ⬜
**Status:** Not Started  
**Priority:** Critical  
**Dependencies:** All previous tasks

**Tasks:**
- [ ] **Skeleton/admin pages:**
  - [ ] Plugin activates without errors
  - [ ] Admin menu appears for admin users only
  - [ ] Settings save and persist
  - [ ] Uninstall cleans up options and tables
- [ ] **File checksum:**
  - [ ] Baseline scan completes
  - [ ] Modified file detected
  - [ ] Lock/restore works
  - [ ] Quarantine/restore works
  - [ ] Mark Safe ignores file
- [ ] **Regex malware scan:**
  - [ ] Detects injected patterns
  - [ ] False positives marked safe
  - [ ] Lock/quarantine actions work
  - [ ] Whitelist prevents repeated alerts
- [ ] **Brute-force lockout:**
  - [ ] IP blocked after threshold
  - [ ] Exponential backoff works
  - [ ] Unblock IP works
  - [ ] Whitelist prevents blocking
  - [ ] Email notification sent
- [ ] **Login anomaly:**
  - [ ] Impossible travel detected
  - [ ] TOR node detected
  - [ ] New country flagged
  - [ ] Mark Safe updates profile
  - [ ] Email sent for critical anomalies
- [ ] **Hardening:**
  - [ ] Security headers present
  - [ ] SSL redirect works
  - [ ] File editing disabled
  - [ ] WP version hidden
  - [ ] User enumeration blocked
  - [ ] .htaccess backup created
- [ ] **WPVulnerability:**
  - [ ] Detects known vuln
  - [ ] Update/disable actions work
  - [ ] Whitelist prevents repeated alerts
  - [ ] Email sent for critical vulns
- [ ] **Auto-disable:**
  - [ ] Snapshot created before disable
  - [ ] Plugin disabled successfully
  - [ ] Notification sent
  - [ ] Restore works
  - [ ] Auto-restore on update works
- [ ] **Firewall:**
  - [ ] SQLi request blocked
  - [ ] XSS request blocked
  - [ ] Whitelist IP bypasses firewall
  - [ ] Country blocking works (Paid)
  - [ ] Logs display correctly
- [ ] **Deep scans:**
  - [ ] DB scan detects injected scripts
  - [ ] Uploads scan detects PHP files
  - [ ] Mark safe works
  - [ ] Remove from DB works
- [ ] **AI analysis:**
  - [ ] Log summary generated
  - [ ] OpenAI API request successful
  - [ ] AI response displayed
  - [ ] Fail-safe handles API unavailability
- [ ] **PDF reports:**
  - [ ] PDF generated successfully
  - [ ] All sections populated
  - [ ] Download works
  - [ ] Scheduled report sent via email
- [ ] **Uptime:**
  - [ ] Server pings site successfully
  - [ ] Downtime detected
  - [ ] Plugin receives uptime data
  - [ ] Dashboard widget displays correctly
  - [ ] Email sent on downtime
- [ ] **Call-home:**
  - [ ] Site ID generated on activation
  - [ ] Registration successful
  - [ ] Daily call-home successful
  - [ ] Signature verified
  - [ ] Pro features unlocked when `pro_enabled = true`
  - [ ] Manual verify works
- [ ] **Grace period:**
  - [ ] Day 1–2: silent cache
  - [ ] Day 3–4: notice appears
  - [ ] Day 7+: Pro features disabled, Free works
- [ ] **Performance:**
  - [ ] Batch processing works on large site
  - [ ] Pause/resume works
  - [ ] File exclusion works
  - [ ] Performance acceptable on large sites

---

### 3E — Minimal Architecture Notes ⬜
**Status:** Not Started  
**Priority:** Low  
**Dependencies:** All previous tasks

**Documentation:**
- [ ] **Client plugin architecture:**
  - [ ] WP admin-only heavy logic (scans, analysis)
  - [ ] Light front hooks for firewall (early execution)
  - [ ] Transients for caching (24h)
  - [ ] WP Cron for scheduled tasks (daily scans, call-home)
- [ ] **Server architecture:**
  - [ ] Call-home API: `/register`, `/verify`
  - [ ] Uptime monitor: ping scheduler + API
  - [ ] Optional: central WPVulnerability cache (reduce API calls)
- [ ] **Storage:**
  - [ ] WP options: `bearmor_site_id`, `bearmor_settings`, `bearmor_license_cache`
  - [ ] DB tables: see schemas in each section
  - [ ] Transients: `bearmor_scan_results`, `bearmor_vulnerability_cache`, `bearmor_ai_analysis`
- [ ] **Phone-home flow:**
  1. Daily ping → POST to `/verify`
  2. Server responds with signed data
  3. Plugin verifies signature
  4. Cache for 24h
  5. If fails 3–4 days → notify admin
  6. If fails ~7 days → disable Pro features
  7. Free tier always works

**Files to Create:**
```
docs/
├── ARCHITECTURE.md
├── API.md (server API documentation)
├── DATABASE.md (schema documentation)
└── DEVELOPMENT.md (setup guide)
```

---

## 🎯 Next Steps

1. **Start with Part 1A** — Plugin Skeleton & Admin Setup
2. **Build incrementally** — Complete each section before moving to next
3. **Test continuously** — Run tests after each feature
4. **Update this planner** — Mark tasks as complete, add notes, adjust priorities

---

## 📝 Notes & Decisions

- **Hosting compatibility:** Use Safe Mode (rename) instead of chmod for file locking
- **Performance:** Batch processing for large sites, file exclusion patterns
- **Security:** All admin actions require `manage_options` capability
- **UX:** Default behavior is passive (alert-first), auto-actions opt-in only
- **Fail-safe:** If API unavailable, show notice but don't break functionality
- **Grace period:** 7 days before disabling Pro features, Free tier always works
- **OpenAI:** Use GPT-3.5-turbo for cost efficiency, max 500 tokens per request
- **PDF library:** TCPDF (lightweight) or mPDF (more features)
- **WPVulnerability:** WPScan API or custom integration
- **Uptime:** Server-side ping every 5 minutes, alert after 10 min downtime

---

## 🐛 Known Issues / Blockers

_(None yet — update as issues arise)_

---

## 🚀 Future Enhancements (Post-MVP)

- [ ] Mobile app for notifications
- [ ] Slack/Discord integration
- [ ] Multi-site support (network-wide dashboard)
- [ ] Advanced AI: anomaly prediction, threat intelligence
- [ ] Integration with external SIEM tools
- [ ] White-label option for agencies
- [ ] API for third-party integrations

---

**Last Updated:** 2025-10-04  
**Version:** 1.0  
**Maintainer:** Bearmor Security Team
