# Answers to Your Questions - 1C File Monitor

## 3) Lock vs Quarantine - What's the Difference?

### 🔒 **Lock** (REMOVED - Too Dangerous!)
- **What it did:** Renamed file to `.locked`
- **Problem:** Breaks WordPress! If WP tries to load the file, site crashes
- **Example:** You locked `class.akismet.php` → Akismet plugin broke → Site crashed
- **Conclusion:** Lock feature is **too risky** and should be **removed or disabled**

### 🗄️ **Quarantine** (SAFE - Recommended!)
- **What it does:** Moves file to isolated directory (`wp-content/bearmor-quarantine/`)
- **Why it's safe:** File is completely removed from active location
- **Benefits:**
  - WordPress won't try to load it
  - File is preserved (can be restored later)
  - Protected directory (`.htaccess` blocks access)
  - Logged in database for tracking
- **Use case:** Suspected malware, modified core files, unknown changes

### ✅ **Mark Safe** (Best for False Positives)
- **What it does:** Updates status to "safe", stops alerting
- **Use case:** You intentionally modified the file (e.g., added custom code)
- **Benefits:** File stays active, no more alerts

---

## 4) When to Use Each Action?

| Scenario | Action | Why |
|----------|--------|-----|
| **Malware detected** | Quarantine | Safely isolate, can analyze later |
| **Modified core file** | Quarantine | Investigate, restore from backup |
| **You edited a file** | Mark Safe | Stop false alerts |
| **Unknown change** | Quarantine first | Better safe than sorry |
| **Lock?** | ❌ DON'T USE | Too dangerous, breaks site |

---

## 5) Baseline vs Integrity Check - How It Works

### 📸 **Baseline Scan** (Run Once, or After Major Changes)

**When to run:**
- ✅ Right after plugin installation (first time)
- ✅ After installing new plugins/themes
- ✅ After WordPress core update
- ✅ After restoring from backup

**What it does:**
1. Scans all files (WP core, plugins, themes)
2. Calculates SHA256 hash for each file
3. Stores in database as "baseline" (the known-good state)
4. Takes 2-60 seconds depending on site size

**Does it detect changes?** 
- ❌ No! It just creates the reference point

**Does it see new plugins?**
- ✅ Yes! If you run it again, it adds new files to baseline
- But it will also mark old files as "changed" if they were modified

---

### 🔍 **Integrity Check** (Run Daily/Weekly)

**When to run:**
- ✅ Daily (automated via cron - will implement in 1H)
- ✅ After suspicious activity
- ✅ Before important updates
- ✅ Manually when you want to check

**What it does:**
1. Reads baseline checksums from database
2. Recalculates current file hashes
3. Compares: current vs baseline
4. Detects: changed, deleted files
5. Takes 0.3-10 seconds (much faster!)

**Does it detect changes?**
- ✅ YES! This is the main detection mechanism

---

## 🔄 Recommended Workflow

### Initial Setup (Once)
```
1. Install plugin
2. Run Baseline Scan
3. Verify 0 changes on dashboard
```

### Regular Monitoring (Automated - Future)
```
Daily (via cron):
1. Run Integrity Check
2. If changes detected → Send notification
3. Admin reviews File Changes page
4. Admin decides: Quarantine or Mark Safe
```

### After Installing New Plugin
```
Option A (Recommended):
1. Install plugin
2. Run Integrity Check
3. New plugin files show as "new"
4. Run Baseline Scan again (updates baseline)

Option B (Simpler):
1. Install plugin
2. Just run Baseline Scan
3. New files added to baseline
```

---

## 🎯 User Actions - Manual or Automatic?

### Current Implementation (Manual)
- ✅ User clicks "Run Baseline Scan" button
- ✅ User clicks "Run Integrity Check" button
- ✅ User reviews changes manually
- ✅ User clicks Lock/Quarantine/Mark Safe

### Future Implementation (1H - Automated)
- ✅ Baseline: Still manual (after major changes)
- ✅ Integrity Check: **Automated daily via WP-Cron**
- ✅ Notifications: Email/Dashboard alerts
- ✅ Actions: Optional auto-quarantine (if enabled in settings)

---

## 🚨 Fix Required: Remove Lock Feature

**Lock is too dangerous!** Here's what we should do:

### Option 1: Remove Lock Completely
- Remove "Lock" button from UI
- Only keep: Quarantine, Mark Safe

### Option 2: Disable Lock for Active Files
- Check if file is loaded by active plugin
- Only allow lock for inactive/unknown files
- Show warning: "This may break your site"

### Option 3: Replace Lock with "Disable Plugin"
- Instead of locking individual files
- Disable the entire plugin via WP API
- Safer and more predictable

**Recommendation:** Remove Lock, keep Quarantine + Mark Safe only.

---

## 📊 Summary

| Feature | When | How Often | Manual/Auto |
|---------|------|-----------|-------------|
| **Baseline Scan** | After install, updates | Once, or as needed | Manual |
| **Integrity Check** | Daily monitoring | Daily (future: auto) | Manual now, Auto later |
| **Quarantine** | Suspicious files | As needed | Manual |
| **Mark Safe** | False positives | As needed | Manual |
| **Lock** | ❌ NEVER | ❌ REMOVE | ❌ Too risky |

---

## ✅ Your Site is Fixed!

I restored the file:
```bash
mv class.akismet.php.locked → class.akismet.php
```

Your site should work now! Refresh and check.
