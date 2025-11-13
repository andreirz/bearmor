<?php
/**
 * File Changes Admin Page
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Handle actions
if ( isset( $_POST['bearmor_action'] ) && check_admin_referer( 'bearmor_file_action' ) ) {
	$action = sanitize_text_field( $_POST['bearmor_action'] );
	$file_path = sanitize_text_field( $_POST['file_path'] );

	switch ( $action ) {
		case 'lock':
			$result = Bearmor_File_Actions::lock_file( $file_path );
			if ( is_wp_error( $result ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html( $result->get_error_message() ) . '</p></div>';
			} else {
				echo '<div class="notice notice-success"><p>File locked successfully!</p></div>';
			}
			break;

		case 'quarantine':
			$result = Bearmor_File_Actions::quarantine_file( $file_path, 'Manual quarantine from admin' );
			if ( is_wp_error( $result ) ) {
				echo '<div class="notice notice-error"><p><strong>Error:</strong> ' . esc_html( $result->get_error_message() ) . '</p></div>';
			} else {
				echo '<div class="notice notice-success"><p><strong>✅ ' . esc_html( $result['message'] ) . '</strong></p>';
				if ( ! empty( $result['warnings'] ) ) {
					foreach ( $result['warnings'] as $warning ) {
						echo '<p>' . esc_html( $warning ) . '</p>';
					}
				}
				echo '</div>';
			}
			break;

		case 'mark_safe':
			Bearmor_File_Actions::mark_safe( $file_path );
			echo '<div class="notice notice-success"><p>File marked as safe!</p></div>';
			break;

		case 'unlock':
			$result = Bearmor_File_Actions::unlock_file( $file_path );
			if ( is_wp_error( $result ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html( $result->get_error_message() ) . '</p></div>';
			} else {
				echo '<div class="notice notice-success"><p>File unlocked successfully!</p></div>';
			}
			break;
	}
}

// Clear bad cache (temporary debug)
global $wp_version;
delete_transient( 'bearmor_core_checksums_' . $wp_version );

// Handle scan actions
if ( isset( $_POST['bearmor_scan'] ) && check_admin_referer( 'bearmor_scan' ) ) {
	$scan_type = sanitize_text_field( $_POST['bearmor_scan'] );
	error_log( 'Bearmor: Scan requested - type: ' . $scan_type );

	if ( $scan_type === 'baseline' ) {
		$results = Bearmor_File_Scanner::run_baseline_scan();
		echo '<div class="notice notice-success"><p>';
		echo 'Baseline scan completed! ';
		echo 'Scanned: ' . esc_html( $results['scanned'] ) . ' files, ';
		echo 'Stored: ' . esc_html( $results['stored'] ) . ' checksums, ';
		echo 'Time: ' . esc_html( $results['time'] ) . 's';
		echo '</p></div>';
	} elseif ( $scan_type === 'integrity' ) {
		$results = Bearmor_File_Scanner::run_integrity_check();
		echo '<div class="notice notice-success"><p>';
		echo '<strong>Integrity check completed!</strong><br>';
		echo 'Checked: ' . esc_html( $results['checked'] ) . ' files, ';
		echo 'Changed: ' . esc_html( $results['changed'] ) . ', ';
		echo 'Time: ' . esc_html( $results['time'] ) . 's';
		echo '</p></div>';
	}
}

// Handle restore from quarantine
if ( isset( $_POST['bearmor_restore'] ) && check_admin_referer( 'bearmor_restore' ) ) {
	$quarantine_id = intval( $_POST['quarantine_id'] );
	$result = Bearmor_File_Actions::restore_from_quarantine( $quarantine_id );
	if ( is_wp_error( $result ) ) {
		echo '<div class="notice notice-error"><p><strong>Error:</strong> ' . esc_html( $result->get_error_message() ) . '</p></div>';
	} else {
		echo '<div class="notice notice-success"><p><strong>✅ File restored successfully!</strong></p></div>';
	}
}

// Check if baseline exists
global $wpdb;
$baseline_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_checksums" );
$baseline_exists = ( $baseline_count > 0 );

// Get changed files
$changed_files = Bearmor_Checksum::get_changed_files();

// Get quarantined files
$quarantined_files = $wpdb->get_results(
	"SELECT * FROM {$wpdb->prefix}bearmor_quarantine WHERE status = 'quarantined' ORDER BY quarantined_at DESC"
);
?>

<?php
// Enqueue dashboard styles
wp_enqueue_style( 'bearmor-dashboard', BEARMOR_PLUGIN_URL . 'assets/css/dashboard.css', array(), BEARMOR_VERSION );
?>

<div class="wrap bearmor-dashboard">
	<h1>File Changes</h1>

	<!-- Scan Actions -->
	<div class="bearmor-scan-actions" style="margin: 20px 0; padding: 24px; background: #fff; border: 1px solid #e0e0e0; border-radius: 10px;">
		<h2 style="margin-top: 0;">Scan Actions</h2>
		
		<?php if ( $baseline_exists ) : ?>
			<!-- Baseline exists - show status and integrity check only -->
			<div style="margin-bottom: 20px; padding: 12px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 6px; color: #155724;">
				<span class="dashicons dashicons-yes-alt" style="color: #28a745;"></span>
				<strong>Baseline scan completed</strong> - <?php echo number_format( $baseline_count ); ?> files monitored.
				<span style="color: #666; font-size: 12px;">(To rebuild baseline, go to Settings → File Monitoring)</span>
			</div>
			
			<form method="post" style="display: inline-block;">
				<?php wp_nonce_field( 'bearmor_scan' ); ?>
				<button type="submit" name="bearmor_scan" value="integrity" class="button button-primary">
					<span class="dashicons dashicons-search" style="margin-top: 3px;"></span> Run Integrity Check
				</button>
				<p class="description">Compares current files against baseline to detect changes</p>
			</form>
		<?php else : ?>
			<!-- No baseline - show warning and baseline button -->
			<div style="margin-bottom: 20px; padding: 12px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; color: #856404;">
				<span class="dashicons dashicons-warning" style="color: #ffc107;"></span>
				<strong>Baseline scan not completed</strong> - File monitoring is not active. Run baseline scan to start monitoring.
			</div>
			
			<form method="post" style="display: inline-block; margin-right: 10px;">
				<?php wp_nonce_field( 'bearmor_scan' ); ?>
				<button type="submit" name="bearmor_scan" value="baseline" class="button button-primary">
					<span class="dashicons dashicons-update" style="margin-top: 3px;"></span> Run Baseline Scan
				</button>
				<p class="description">Creates initial checksums for all files (WP core, plugins, themes)</p>
			</form>
		<?php endif; ?>
	</div>

	<!-- Changed Files List -->
	<h2>Changed Files (<?php echo count( $changed_files ); ?>)</h2>

	<?php if ( empty( $changed_files ) ) : ?>
		<?php if ( $baseline_exists ) : ?>
			<p>No file changes detected. All files match the baseline.</p>
		<?php else : ?>
			<p>No file changes detected. Run a baseline scan first, then an integrity check to detect changes.</p>
		<?php endif; ?>
	<?php else : ?>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width: 35%;">File Path</th>
					<th style="width: 25%;">Belongs To</th>
					<th style="width: 15%;">Last Checked</th>
					<th style="width: 10%;">Status</th>
					<th style="width: 15%;">Actions</th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $changed_files as $file ) : ?>
					<?php
					// Detect plugin/theme for this file
					$belongs_to = '';
					$belongs_to_short = '-';
					
					if ( strpos( $file->file_path, 'wp-content/plugins/' ) === 0 ) {
						$path_parts = explode( '/', str_replace( 'wp-content/plugins/', '', $file->file_path ) );
						$plugin_dir = $path_parts[0];
						$plugins = get_plugins();
						foreach ( $plugins as $plugin_file => $plugin_data ) {
							if ( strpos( $plugin_file, $plugin_dir . '/' ) === 0 ) {
								$is_active = is_plugin_active( $plugin_file ) ? ' ⚠️ ACTIVE' : '';
								$belongs_to = 'Plugin: ' . $plugin_data['Name'] . $is_active;
								$belongs_to_short = $plugin_data['Name'] . $is_active;
								break;
							}
						}
					} elseif ( strpos( $file->file_path, 'wp-content/themes/' ) === 0 ) {
						$path_parts = explode( '/', str_replace( 'wp-content/themes/', '', $file->file_path ) );
						$theme_slug = $path_parts[0];
						$is_active_theme = ( $theme_slug === get_stylesheet() ) ? ' ⚠️ ACTIVE' : '';
						$belongs_to = 'Theme: ' . ucfirst( $theme_slug ) . $is_active_theme;
						$belongs_to_short = ucfirst( $theme_slug ) . $is_active_theme;
					} elseif ( strpos( $file->file_path, 'wp-admin' ) === 0 || strpos( $file->file_path, 'wp-includes' ) === 0 ) {
						$belongs_to_short = 'WordPress Core';
					}
					?>
					
					<tr>
						<td>
							<strong><?php echo esc_html( $file->file_path ); ?></strong>
							<br>
							<small style="color: #666;">
								Size: <?php echo esc_html( size_format( $file->file_size ) ); ?> | 
								<a href="#" class="bearmor-preview-link" data-file="<?php echo esc_attr( $file->file_path ); ?>" data-preview-id="preview-<?php echo esc_attr( md5( $file->file_path ) ); ?>" onclick="bearmor_toggle_preview(this); return false;">View Preview</a>
							</small>
						</td>
						<td>
							<strong><?php echo esc_html( $belongs_to_short ); ?></strong>
						</td>
						<td>
							<?php echo esc_html( human_time_diff( strtotime( $file->last_checked ), current_time( 'timestamp' ) ) . ' ago' ); ?>
						</td>
						<td>
							<span class="bearmor-status-badge bearmor-status-<?php echo esc_attr( $file->status ); ?>">
								<?php echo esc_html( ucfirst( $file->status ) ); ?>
							</span>
						</td>
						<td>
							<form method="post" style="display: inline;" onsubmit="return confirm('⚠️ WARNING:\n\nFile: <?php echo esc_js( $file->file_path ); ?>\n<?php echo esc_js( $belongs_to ); ?>\n\nThis action will:\n1. Deactivate plugin/theme if active\n2. Quarantine the file to isolated directory\n3. May affect site functionality\n\nContinue?');">
								<?php wp_nonce_field( 'bearmor_file_action' ); ?>
								<input type="hidden" name="file_path" value="<?php echo esc_attr( $file->file_path ); ?>">
								
								<button type="submit" name="bearmor_action" value="quarantine" class="button button-small bearmor-btn-quarantine">
									Quarantine
								</button>
							</form>
							
							<form method="post" style="display: inline;">
								<?php wp_nonce_field( 'bearmor_file_action' ); ?>
								<input type="hidden" name="file_path" value="<?php echo esc_attr( $file->file_path ); ?>">
								
								<button type="submit" name="bearmor_action" value="mark_safe" class="button button-small bearmor-btn-safe">
									Mark Safe
								</button>
							</form>
					</tr>
					<tr class="bearmor-preview-row" id="preview-<?php echo esc_attr( md5( $file->file_path ) ); ?>" style="display: none;">
						<td colspan="5" style="background: #f9f9f9; padding: 15px;">
							<div class="bearmor-preview-content">
								<div class="bearmor-preview-loading">Loading preview...</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<!-- Quarantined Files List -->
	<?php
	// Count actual files that exist
	$actual_count = 0;
	foreach ( $quarantined_files as $qf ) {
		if ( file_exists( ABSPATH . $qf->quarantined_path ) ) {
			$actual_count++;
		}
	}
	?>
	<h2 style="margin-top: 40px; color: #666;">Quarantined Files (<?php echo $actual_count; ?>)</h2>

	<?php if ( $actual_count === 0 ) : ?>
		<p style="color: #999;">No files in quarantine.</p>
	<?php else : ?>
		<table class="wp-list-table widefat fixed striped bearmor-quarantine-table">
			<thead>
				<tr>
					<th style="width: 45%;">Original File Path</th>
					<th style="width: 15%;">Quarantined</th>
					<th style="width: 30%;">Reason</th>
					<th style="width: 10%;">Actions</th>
				</tr>
			</thead>
			<tbody>
				<?php 
				$actual_quarantined = 0;
				foreach ( $quarantined_files as $qfile ) : 
					// Only show if file actually exists in quarantine
					$quarantine_file_path = ABSPATH . $qfile->quarantined_path;
					if ( ! file_exists( $quarantine_file_path ) ) {
						// File doesn't exist, update database status
						$wpdb->update(
							$wpdb->prefix . 'bearmor_quarantine',
							array( 'status' => 'deleted' ),
							array( 'id' => $qfile->id ),
							array( '%s' ),
							array( '%d' )
						);
						continue; // Skip this record
					}
					$actual_quarantined++;
				?>
					<tr>
						<td>
							<span style="color: #666;"><?php echo esc_html( $qfile->file_path ); ?></span>
							<br>
							<small style="color: #999; font-size: 11px;">Quarantined: <?php echo esc_html( $qfile->quarantined_path ); ?></small>
						</td>
						<td style="color: #999; font-size: 12px;">
							<?php echo esc_html( human_time_diff( strtotime( $qfile->quarantined_at ), current_time( 'timestamp' ) ) . ' ago' ); ?>
						</td>
						<td style="color: #999; font-size: 12px;">
							<?php echo esc_html( $qfile->reason ); ?>
						</td>
						<td>
							<form method="post" style="display: inline;">
								<?php wp_nonce_field( 'bearmor_restore' ); ?>
								<input type="hidden" name="quarantine_id" value="<?php echo esc_attr( $qfile->id ); ?>">
								
								<button type="submit" name="bearmor_restore" class="bearmor-restore-link">
									Restore
								</button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

</div>

<style>
.bearmor-status-badge {
	padding: 3px 8px;
	border-radius: 3px;
	font-size: 11px;
	font-weight: 600;
	text-transform: uppercase;
}

.bearmor-status-changed {
	background: #FFF3CD;
	color: #856404;
}

.bearmor-status-safe {
	background: #D4EDDA;
	color: #155724;
}

.bearmor-status-deleted {
	background: #F8D7DA;
	color: #721C24;
}

.bearmor-btn-quarantine {
	background: #F44336 !important;
	color: #fff !important;
	border-color: #F44336 !important;
	font-size: 11px !important;
	padding: 4px 10px !important;
}

.bearmor-btn-quarantine:hover {
	background: #D32F2F !important;
	border-color: #D32F2F !important;
}

.bearmor-btn-safe {
	background: #4CAF50 !important;
	color: #fff !important;
	border-color: #4CAF50 !important;
	font-size: 11px !important;
	padding: 4px 10px !important;
}

.bearmor-btn-safe:hover {
	background: #388E3C !important;
	border-color: #388E3C !important;
}

.bearmor-btn-restore {
	background: #2196F3 !important;
	color: #fff !important;
	border-color: #2196F3 !important;
	font-size: 11px !important;
	padding: 4px 10px !important;
}

.bearmor-btn-restore:hover {
	background: #1976D2 !important;
	border-color: #1976D2 !important;
}

/* Quarantine Table Styling */
.bearmor-quarantine-table {
	opacity: 0.7;
	background: #f9f9f9;
}

.bearmor-quarantine-table thead th {
	background: #f0f0f0;
	color: #666;
	font-size: 12px;
	padding: 8px 10px;
}

.bearmor-quarantine-table tbody td {
	padding: 8px 10px;
	font-size: 12px;
}

.bearmor-restore-link {
	background: none !important;
	border: none !important;
	color: #2196F3 !important;
	text-decoration: underline;
	cursor: pointer;
	padding: 0 !important;
	font-size: 12px;
	box-shadow: none !important;
}

.bearmor-restore-link:hover {
	color: #1976D2 !important;
	background: none !important;
	border: none !important;
}

.bearmor-preview-link {
	color: #0073aa !important;
	text-decoration: none !important;
	font-weight: 500;
}

.bearmor-preview-link:hover {
	color: #005177 !important;
	text-decoration: underline !important;
}

.bearmor-preview-content {
	max-height: 600px;
	overflow-y: auto;
	background: #fff;
	border: 1px solid #ddd;
	border-radius: 3px;
}

.bearmor-preview-content pre {
	margin: 0;
	padding: 15px;
	font-family: 'Courier New', monospace;
	font-size: 12px;
	line-height: 1.5;
	white-space: pre-wrap;
	word-wrap: break-word;
}

.bearmor-preview-content .line-numbers {
	display: inline-block;
	width: 40px;
	color: #999;
	text-align: right;
	padding-right: 10px;
	border-right: 1px solid #ddd;
	margin-right: 10px;
	user-select: none;
}

.bearmor-preview-loading {
	padding: 20px;
	text-align: center;
	color: #666;
}

.bearmor-preview-error {
	padding: 20px;
	color: #d63638;
	background: #fcf0f1;
	border-radius: 3px;
}

.bearmor-preview-truncated {
	padding: 10px;
	background: #fff3cd;
	border: 1px solid #ffc107;
	border-radius: 3px;
	margin-bottom: 10px;
	color: #856404;
	font-weight: bold;
}
</style>

<script>
function bearmor_toggle_preview(element) {
	var filePath = element.getAttribute('data-file');
	var previewId = element.getAttribute('data-preview-id');
	var previewRow = document.getElementById(previewId);
	
	if (!previewRow) {
		console.error('Preview row not found:', previewId);
		return;
	}
	
	if (previewRow.style.display === 'none' || previewRow.style.display === '') {
		// Show preview
		previewRow.style.display = 'table-row';
		element.textContent = 'Hide Preview';
		
		// Load content if not already loaded
		if (!element.hasAttribute('data-loaded')) {
			bearmor_load_preview(filePath, previewId);
			element.setAttribute('data-loaded', 'true');
		}
	} else {
		// Hide preview
		previewRow.style.display = 'none';
		element.textContent = 'View Preview';
	}
}

function bearmor_load_preview(filePath, previewId) {
	var previewRow = document.getElementById(previewId);
	var contentDiv = previewRow.querySelector('.bearmor-preview-content');
	
	// AJAX request to load file content
	var xhr = new XMLHttpRequest();
	xhr.open('POST', ajaxurl, true);
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	
	xhr.onload = function() {
		if (xhr.status === 200) {
			var response = JSON.parse(xhr.responseText);
			if (response.success) {
				contentDiv.innerHTML = response.data.html;
			} else {
				contentDiv.innerHTML = '<div class="bearmor-preview-error">Error: ' + response.data.message + '</div>';
			}
		} else {
			contentDiv.innerHTML = '<div class="bearmor-preview-error">Failed to load preview</div>';
		}
	};
	
	xhr.send('action=bearmor_preview_file&file_path=' + encodeURIComponent(filePath) + '&nonce=<?php echo wp_create_nonce( 'bearmor_preview' ); ?>');
}
</script>
