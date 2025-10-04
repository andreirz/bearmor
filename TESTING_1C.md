# 🧪 Testing Guide: 1C - File Change Monitor

## How It Works

### Overview
The File Change Monitor uses **SHA256 checksums** to detect when files have been modified, added, or deleted. It works in two phases:

1. **Baseline Scan** - Creates initial checksums for all files
2. **Integrity Check** - Compares current files against baseline to detect changes

### Technical Flow

```
1. Baseline Scan
   ├── Scans WP core files (excluding wp-content)
   ├── Scans all plugin files
   ├── Scans all theme files
   ├── Excludes: uploads, cache, logs, node_modules, vendor
   ├── Calculates SHA256 hash for each file
   └── Stores in database: bearmor_file_checksums

2. Integrity Check
   ├── Reads all baseline checksums from database
   ├── Recalculates current file hashes
   ├── Compares current vs baseline
   ├── Detects: changed, deleted files
   ├── Logs changes in: bearmor_file_changes
   └── Updates status in: bearmor_file_checksums

3. File Actions
   ├── Lock: Renames file to .locked (safe mode)
   ├── Quarantine: Moves to wp-content/bearmor-quarantine/
   ├── Restore: Moves back from quarantine
   └── Mark Safe: Updates status, ignores in future scans
```

### Database Tables

**bearmor_file_checksums**
- Stores baseline checksums
- Tracks file status (baseline, changed, deleted, safe)
- Records last check time

**bearmor_file_changes**
- Logs detected changes
- Stores old/new checksums
- Tracks actions taken

**bearmor_quarantine**
- Records quarantined files
- Stores original and quarantine paths
- Tracks restore status

---

## 🧪 Testing Steps

### Step 1: Deactivate & Reactivate Plugin
This will create the new database tables.

1. Go to **Plugins** → Find "Bearmor Security"
2. Click **Deactivate**
3. Click **Activate**
4. ✅ Check: No errors appear

### Step 2: Run Baseline Scan

1. Go to **Bearmor Security** → **File Changes**
2. Click **"Run Baseline Scan"** button
3. Wait for completion (may take 30-60 seconds depending on site size)
4. ✅ Expected result:
   ```
   Baseline scan completed! 
   Scanned: ~2000-5000 files
   Stored: ~2000-5000 checksums
   Time: 30-60s
   ```

### Step 3: Verify Dashboard Shows Zero Changes

1. Go to **Bearmor Security** → **Dashboard**
2. Look at "File Changes" widget
3. ✅ Expected: Shows **0** (green)

### Step 4: Modify a File to Test Detection

1. Open any plugin file (e.g., `wp-content/plugins/akismet/class.akismet.php`)
2. Add a comment at the top:
   ```php
   <?php
   // Test modification for Bearmor
   ```
3. Save the file

### Step 5: Run Integrity Check

1. Go to **Bearmor Security** → **File Changes**
2. Click **"Run Integrity Check"** button
3. ✅ Expected result:
   ```
   Integrity check completed!
   Checked: ~2000-5000 files
   Changed: 1
   Deleted: 0
   Time: 20-40s
   ```

### Step 6: Verify Dashboard Shows Change

1. Go to **Bearmor Security** → **Dashboard**
2. Look at "File Changes" widget
3. ✅ Expected: Shows **1** (red/critical color)
4. Click **"View Details"**

### Step 7: Test File Actions

#### Test 1: Lock File
1. In the File Changes list, find your modified file
2. Click **"Lock"** button
3. ✅ Expected: "File locked successfully!"
4. ✅ Check: File renamed to `class.akismet.php.locked` on server

#### Test 2: Unlock File
1. Click **"Unlock"** button (you may need to add this button)
2. ✅ Expected: File renamed back to original

#### Test 3: Quarantine File
1. Click **"Quarantine"** button
2. ✅ Expected: "File quarantined successfully!"
3. ✅ Check: File moved to `wp-content/bearmor-quarantine/[timestamp]_class.akismet.php`
4. ✅ Check: Original file no longer exists

#### Test 4: Mark Safe
1. Before quarantining, click **"Mark Safe"** button
2. ✅ Expected: "File marked as safe!"
3. ✅ Check: File status changes to "Safe"
4. Run integrity check again
5. ✅ Expected: File no longer appears in changed files list

---

## 🔍 What to Check

### Database Verification
Run these SQL queries in phpMyAdmin:

```sql
-- Check baseline checksums
SELECT COUNT(*) FROM wp_bearmor_file_checksums;
-- Should show 2000-5000 records

-- Check changed files
SELECT * FROM wp_bearmor_file_checksums WHERE status = 'changed';
-- Should show your modified file

-- Check file changes log
SELECT * FROM wp_bearmor_file_changes;
-- Should show change records

-- Check quarantine
SELECT * FROM wp_bearmor_quarantine;
-- Should show quarantined files if you tested quarantine
```

### File System Verification

```bash
# Check quarantine directory exists
ls -la wp-content/bearmor-quarantine/

# Check .htaccess protection
cat wp-content/bearmor-quarantine/.htaccess
# Should show: "Order deny,allow\nDeny from all"

# Check locked files
find wp-content/plugins -name "*.locked"
```

---

## ⚠️ Known Limitations

1. **Large Sites**: Baseline scan may timeout on very large sites (10,000+ files)
   - Solution: Will implement batch processing in 2H

2. **Safe Mode Only**: Currently only supports rename-based locking
   - chmod 000 mode disabled for hosting compatibility

3. **No Diff View**: Can't see what changed in the file yet
   - Will be added in future update

---

## 🐛 Troubleshooting

### "Baseline scan completed but 0 files stored"
- Check file permissions
- Check database connection
- Look for PHP errors in debug.log

### "Integrity check shows no changes but I modified a file"
- Make sure you ran baseline scan first
- Check if file is in excluded patterns
- Verify file path is correct

### "Lock/Quarantine fails"
- Check file permissions (need write access)
- Check disk space
- Verify quarantine directory exists and is writable

---

## ✅ Success Criteria

- [x] Baseline scan completes without errors
- [x] Integrity check detects modified files
- [x] Dashboard shows correct file change count
- [x] File Changes page lists changed files
- [x] Lock action renames file to .locked
- [x] Quarantine moves file to quarantine directory
- [x] Mark Safe updates status and removes from list
- [x] All actions are logged in audit log

---

## 📝 Notes

- Baseline scan should be run after plugin installation
- Integrity check should run daily (will be automated in future)
- Always test actions on non-critical files first
- Quarantined files can be restored from the quarantine table
