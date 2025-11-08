<?php
/**
 * Deep Scan Admin Page
 * Scan database and uploads for malicious content
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if Pro feature is available
$is_pro = Bearmor_License::is_pro();

// Get active tab
$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'database';

// Load saved results from database
global $wpdb;
$db_results = $wpdb->get_results(
	"SELECT * FROM {$wpdb->prefix}bearmor_deep_scan_results 
	WHERE scan_type = 'database' AND status = 'pending' 
	ORDER BY detected_at DESC",
	ARRAY_A
);

$uploads_results = $wpdb->get_results(
	"SELECT * FROM {$wpdb->prefix}bearmor_deep_scan_results 
	WHERE scan_type = 'uploads' AND status = 'pending' 
	ORDER BY detected_at DESC",
	ARRAY_A
);
?>

<div class="wrap">
	<h1>🔍 Deep Scan</h1>
	<p>Scan your database and uploads folder for malicious code injections.</p>

	<?php if ( ! $is_pro ) : ?>
	<!-- Pro Feature Overlay -->
	<div style="background: #f5f5f5; border: 2px solid #ddd; border-radius: 8px; padding: 40px; text-align: center; margin: 20px 0;">
		<h2 style="color: #666; margin-top: 0;">🔒 Pro Feature</h2>
		<p style="color: #999; font-size: 16px; margin: 10px 0;">
			Deep Scan is available for Pro members only.
		</p>
		<p style="color: #999; margin: 20px 0;">
			Scan your database and uploads folder for hidden malware, injected code, and suspicious files.
		</p>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="button button-primary" style="background: #8269FF; border-color: #8269FF;">
			Upgrade to Pro
		</a>
	</div>

	<!-- Example Preview (grayed out) -->
	<div style="opacity: 0.5; filter: grayscale(100%); margin-top: 30px;">
		<h3 style="color: #999;">Example Scan Results:</h3>
		<table class="wp-list-table widefat fixed striped" style="font-size: 12px;">
			<thead>
				<tr>
					<th>Location</th>
					<th style="width: 100px;">Threat Type</th>
					<th style="width: 80px;">Severity</th>
					<th style="width: 100px;">Detected</th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td>
						<strong>wp_posts.post_content (ID: 42)</strong><br>
						<small style="color: #999;">database scan</small>
					</td>
					<td>Malicious Script</td>
					<td>
						<span style="background: #d63638; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">
							Critical
						</span>
					</td>
					<td><small>Oct 17, 14:32</small></td>
				</tr>
				<tr>
					<td>
						<strong>/wp-content/uploads/2024/01/shell.php</strong><br>
						<small style="color: #999;">uploads scan</small>
					</td>
					<td>Web Shell</td>
					<td>
						<span style="background: #d63638; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">
							Critical
						</span>
					</td>
					<td><small>Oct 16, 09:15</small></td>
				</tr>
			</tbody>
		</table>
		<p style="text-align: center; color: #999; font-size: 11px; margin-top: 10px;">
			<em>Demo data - This is what you'll see with Pro</em>
		</p>
	</div>
	<?php endif; ?>

	<?php if ( $is_pro ) : ?>
	<!-- Tabs -->
	<h2 class="nav-tab-wrapper" style="margin-top: 20px;">
		<a href="?page=bearmor-deep-scan&tab=database" class="nav-tab <?php echo $active_tab === 'database' ? 'nav-tab-active' : ''; ?>">
			Database Scan
		</a>
		<a href="?page=bearmor-deep-scan&tab=uploads" class="nav-tab <?php echo $active_tab === 'uploads' ? 'nav-tab-active' : ''; ?>">
			Uploads Scan
		</a>
	</h2>

	<div style="margin-top: 20px;">
		<?php if ( $active_tab === 'database' ) : ?>
			<!-- Database Scan Tab -->
			<div class="card" style="max-width: 100%;">
				<h2>Database Scan</h2>
				<p>Scans posts, comments, and options for malicious code (scripts, iframes, obfuscated code).</p>
				
				<button id="start-db-scan" class="button button-primary button-hero" style="margin-top: 10px;">
					🔍 Start Database Scan
				</button>

				<!-- Progress Bar -->
				<div id="db-scan-progress" style="display: none; margin-top: 20px;">
					<div style="background: #f0f0f0; border-radius: 5px; height: 30px; position: relative; overflow: hidden;">
						<div id="db-progress-bar" style="background: linear-gradient(90deg, #2271b1, #135e96); height: 100%; width: 0%; transition: width 0.3s;"></div>
						<span id="db-progress-text" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-weight: 600; color: #333;">0%</span>
					</div>
					<p id="db-scan-status" style="margin-top: 10px; color: #666;">Initializing scan...</p>
				</div>

				<!-- Results -->
				<div id="db-scan-results" style="margin-top: 20px;">
					<?php if ( ! empty( $db_results ) ) : ?>
						<h3>⚠️ Found <?php echo count( $db_results ); ?> potential threats:</h3>
						<table class="wp-list-table widefat fixed striped">
							<thead>
								<tr>
									<th style="width: 25%;">Location</th>
									<th style="width: 20%;">Pattern</th>
									<th style="width: 30%;">Matched Code</th>
									<th style="width: 10%;">Severity</th>
									<th style="width: 15%;">Actions</th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $db_results as $result ) : ?>
									<?php
									$severity_color = $result['severity'] === 'critical' ? '#d63638' : ( $result['severity'] === 'high' ? '#dba617' : '#00a32a' );
									$matched_preview = strlen( $result['matched_code'] ) > 60 ? substr( $result['matched_code'], 0, 60 ) . '...' : $result['matched_code'];
									?>
									<tr>
										<td><?php echo esc_html( $result['location'] ); ?></td>
										<td><code><?php echo esc_html( $result['pattern'] ); ?></code></td>
										<td><code style="font-size: 11px; word-break: break-all;"><?php echo esc_html( $matched_preview ); ?></code></td>
										<td><span style="color: <?php echo $severity_color; ?>; font-weight: 600;"><?php echo strtoupper( $result['severity'] ); ?></span></td>
										<td>
											<button class="button button-small view-threat" data-id="<?php echo $result['id']; ?>" data-type="database">View</button>
											<button class="button button-small button-link-delete clean-threat" data-id="<?php echo $result['id']; ?>" data-item-id="<?php echo $result['item_id']; ?>" data-item-type="<?php echo $result['item_type']; ?>">Clean</button>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
				</div>
			</div>

		<?php elseif ( $active_tab === 'uploads' ) : ?>
			<!-- Uploads Scan Tab -->
			<div class="card" style="max-width: 100%;">
				<h2>Uploads Scan</h2>
				<p>Scans wp-content/uploads for PHP files, polyglot files, and suspicious extensions.</p>
				
				<button id="start-uploads-scan" class="button button-primary button-hero" style="margin-top: 10px;">
					🔍 Start Uploads Scan
				</button>

				<!-- Progress Bar -->
				<div id="uploads-scan-progress" style="display: none; margin-top: 20px;">
					<div style="background: #f0f0f0; border-radius: 5px; height: 30px; position: relative; overflow: hidden;">
						<div id="uploads-progress-bar" style="background: linear-gradient(90deg, #2271b1, #135e96); height: 100%; width: 0%; transition: width 0.3s;"></div>
						<span id="uploads-progress-text" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-weight: 600; color: #333;">0%</span>
					</div>
					<p id="uploads-scan-status" style="margin-top: 10px; color: #666;">Initializing scan...</p>
				</div>

				<!-- Results -->
				<div id="uploads-scan-results" style="margin-top: 20px;">
					<?php if ( ! empty( $uploads_results ) ) : ?>
						<h3>⚠️ Found <?php echo count( $uploads_results ); ?> suspicious files:</h3>
						<table class="wp-list-table widefat fixed striped">
							<thead>
								<tr>
									<th style="width: 50%;">File</th>
									<th style="width: 25%;">Pattern</th>
									<th style="width: 10%;">Severity</th>
									<th style="width: 15%;">Actions</th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $uploads_results as $result ) : ?>
									<?php $severity_color = $result['severity'] === 'critical' ? '#d63638' : ( $result['severity'] === 'high' ? '#dba617' : '#00a32a' ); ?>
									<tr>
										<td><code style="font-size: 11px; word-break: break-all;"><?php echo esc_html( $result['location'] ); ?></code></td>
										<td><code><?php echo esc_html( $result['pattern'] ); ?></code></td>
										<td><span style="color: <?php echo $severity_color; ?>; font-weight: 600;"><?php echo strtoupper( $result['severity'] ); ?></span></td>
										<td>
											<button class="button button-small quarantine-file" data-id="<?php echo $result['id']; ?>" data-file="<?php echo esc_attr( $result['item_id'] ); ?>">Quarantine</button>
											<button class="button button-small delete-file" data-id="<?php echo $result['id']; ?>" data-file="<?php echo esc_attr( $result['item_id'] ); ?>">Delete</button>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
				</div>
			</div>
		<?php endif; ?>
	</div>
</div>

<!-- View Threat Modal -->
<div id="view-threat-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 100000;">
	<div style="position: relative; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #fff; padding: 30px; border-radius: 8px; max-width: 800px; max-height: 80vh; overflow-y: auto;">
		<h2>Threat Details</h2>
		<div id="threat-details"></div>
		<button id="close-modal" class="button button-primary" style="margin-top: 20px;">Close</button>
	</div>
</div>

<script>
jQuery(document).ready(function($) {
	// Database Scan
	$('#start-db-scan').on('click', function() {
		$(this).prop('disabled', true);
		$('#db-scan-progress').show();
		$('#db-scan-results').html('');
		
		scanDatabase(0, []);
	});

	function scanDatabase(offset, allResults) {
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'bearmor_scan_database',
				nonce: '<?php echo wp_create_nonce( 'bearmor_deep_scan' ); ?>',
				offset: offset
			},
			success: function(response) {
				if (response.success) {
					allResults = allResults.concat(response.data.results);
					
					// Update progress
					var progress = response.data.progress;
					$('#db-progress-bar').css('width', progress + '%');
					$('#db-progress-text').text(progress + '%');
					$('#db-scan-status').text(response.data.status);

					if (response.data.complete) {
						// Scan complete
						$('#db-scan-status').html('<strong style="color: #00a32a;">✅ Scan complete!</strong>');
						displayDatabaseResults(allResults);
						$('#start-db-scan').prop('disabled', false);
					} else {
						// Continue scanning
						scanDatabase(response.data.next_offset, allResults);
					}
				} else {
					alert('Error: ' + response.data.message);
					$('#start-db-scan').prop('disabled', false);
				}
			},
			error: function() {
				alert('Scan failed. Please try again.');
				$('#start-db-scan').prop('disabled', false);
			}
		});
	}

	function displayDatabaseResults(results) {
		if (results.length === 0) {
			$('#db-scan-results').html('<div class="notice notice-success"><p>✅ No threats found in database!</p></div>');
			return;
		}

		var html = '<h3>⚠️ Found ' + results.length + ' potential threats:</h3>';
		html += '<table class="wp-list-table widefat fixed striped">';
		html += '<thead><tr><th style="width: 25%;">Location</th><th style="width: 20%;">Pattern</th><th style="width: 30%;">Matched Code</th><th style="width: 10%;">Severity</th><th style="width: 15%;">Actions</th></tr></thead><tbody>';

		results.forEach(function(item) {
			var severityColor = item.severity === 'critical' ? '#d63638' : (item.severity === 'high' ? '#dba617' : '#00a32a');
			var matched = item.matched || 'N/A';
			var matchedPreview = matched.length > 60 ? matched.substring(0, 60) + '...' : matched;
			var dbId = item.db_id || item.id; // Use db_id from fresh scan, or id from page load
			
			html += '<tr>';
			html += '<td>' + $('<div>').text(item.location || 'Unknown').html() + '</td>';
			html += '<td><code>' + $('<div>').text(item.pattern || 'Unknown').html() + '</code></td>';
			html += '<td><code style="font-size: 11px; word-break: break-all;">' + $('<div>').text(matchedPreview).html() + '</code></td>';
			html += '<td><span style="color: ' + severityColor + '; font-weight: 600;">' + (item.severity || 'UNKNOWN').toUpperCase() + '</span></td>';
			html += '<td>';
			html += '<button class="button button-small view-threat" data-id="' + dbId + '" data-type="database">View</button> ';
			html += '<button class="button button-small button-link-delete clean-threat" data-id="' + dbId + '" data-item-id="' + item.id + '" data-item-type="' + item.type + '">Clean</button>';
			html += '</td>';
			html += '</tr>';
		});

		html += '</tbody></table>';
		$('#db-scan-results').html(html);
	}

	// Uploads Scan
	$('#start-uploads-scan').on('click', function() {
		$(this).prop('disabled', true);
		$('#uploads-scan-progress').show();
		$('#uploads-scan-results').html('');
		
		scanUploads(0, []);
	});

	function scanUploads(offset, allResults) {
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'bearmor_scan_uploads',
				nonce: '<?php echo wp_create_nonce( 'bearmor_deep_scan' ); ?>',
				offset: offset
			},
			success: function(response) {
				if (response.success) {
					allResults = allResults.concat(response.data.results);
					
					// Update progress
					var progress = response.data.progress;
					$('#uploads-progress-bar').css('width', progress + '%');
					$('#uploads-progress-text').text(progress + '%');
					$('#uploads-scan-status').text(response.data.status);

					if (response.data.complete) {
						// Scan complete
						$('#uploads-scan-status').html('<strong style="color: #00a32a;">✅ Scan complete!</strong>');
						displayUploadsResults(allResults);
						$('#start-uploads-scan').prop('disabled', false);
					} else {
						// Continue scanning
						scanUploads(response.data.next_offset, allResults);
					}
				} else {
					alert('Error: ' + response.data.message);
					$('#start-uploads-scan').prop('disabled', false);
				}
			},
			error: function() {
				alert('Scan failed. Please try again.');
				$('#start-uploads-scan').prop('disabled', false);
			}
		});
	}

	function displayUploadsResults(results) {
		if (results.length === 0) {
			$('#uploads-scan-results').html('<div class="notice notice-success"><p>✅ No threats found in uploads!</p></div>');
			return;
		}

		var html = '<h3>⚠️ Found ' + results.length + ' suspicious files:</h3>';
		html += '<table class="wp-list-table widefat fixed striped">';
		html += '<thead><tr><th style="width: 50%;">File</th><th style="width: 25%;">Pattern</th><th style="width: 10%;">Severity</th><th style="width: 15%;">Actions</th></tr></thead><tbody>';

		results.forEach(function(item) {
			var severityColor = item.severity === 'critical' ? '#d63638' : (item.severity === 'high' ? '#dba617' : '#00a32a');
			html += '<tr>';
			html += '<td><code style="font-size: 11px; word-break: break-all;">' + $('<div>').text(item.location || 'Unknown').html() + '</code></td>';
			html += '<td><code>' + $('<div>').text(item.pattern || 'Unknown').html() + '</code></td>';
			html += '<td><span style="color: ' + severityColor + '; font-weight: 600;">' + (item.severity || 'UNKNOWN').toUpperCase() + '</span></td>';
			html += '<td><button class="button button-small">Quarantine</button> <button class="button button-small">Delete</button></td>';
			html += '</tr>';
		});

		html += '</tbody></table>';
		$('#uploads-scan-results').html(html);
	}

	// View Threat
	$(document).on('click', '.view-threat', function() {
		var id = $(this).data('id');
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'bearmor_view_threat',
				nonce: '<?php echo wp_create_nonce( 'bearmor_deep_scan' ); ?>',
				id: id
			},
			success: function(response) {
				if (response.success) {
					$('#threat-details').html(response.data.html);
					$('#view-threat-modal').fadeIn();
				}
			}
		});
	});

	// Close modal
	$('#close-modal, #view-threat-modal').on('click', function(e) {
		if (e.target === this) {
			$('#view-threat-modal').fadeOut();
		}
	});

	// Clean Threat (remove malicious code from database)
	$(document).on('click', '.clean-threat', function() {
		if (!confirm('REMOVE this malicious code from the database? This will modify your content!')) return;
		
		var id = $(this).data('id');
		var itemId = $(this).data('item-id');
		var itemType = $(this).data('item-type');
		var $row = $(this).closest('tr');
		
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'bearmor_clean_threat',
				nonce: '<?php echo wp_create_nonce( 'bearmor_deep_scan' ); ?>',
				id: id,
				item_id: itemId,
				item_type: itemType
			},
			success: function(response) {
				if (response.success) {
					$row.fadeOut(function() {
						$(this).remove();
						location.reload();
					});
					alert('Malicious code removed successfully!');
				} else {
					alert('Error: ' + response.data.message);
				}
			}
		});
	});

	// Quarantine File
	$(document).on('click', '.quarantine-file', function() {
		if (!confirm('Quarantine this file? It will be moved to a safe location.')) return;
		
		var id = $(this).data('id');
		var file = $(this).data('file');
		var $row = $(this).closest('tr');
		
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'bearmor_quarantine_file',
				nonce: '<?php echo wp_create_nonce( 'bearmor_deep_scan' ); ?>',
				id: id,
				file: file
			},
			success: function(response) {
				if (response.success) {
					$row.fadeOut(function() {
						$(this).remove();
						location.reload();
					});
					alert('File quarantined successfully!');
				} else {
					alert('Error: ' + response.data.message);
				}
			}
		});
	});

	// Delete File
	$(document).on('click', '.delete-file', function() {
		if (!confirm('PERMANENTLY DELETE this file? This cannot be undone!')) return;
		
		var id = $(this).data('id');
		var file = $(this).data('file');
		var $row = $(this).closest('tr');
		var $btn = $(this);
		
		$btn.prop('disabled', true).text('Deleting...');
		
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'bearmor_delete_file',
				nonce: '<?php echo wp_create_nonce( 'bearmor_deep_scan' ); ?>',
				id: id,
				file: file
			},
			success: function(response) {
				if (response.success) {
					alert('File deleted successfully!');
					$row.fadeOut(function() {
						$(this).remove();
					});
				} else {
					alert('Error: ' + (response.data ? response.data.message : 'Unknown error'));
					$btn.prop('disabled', false).text('Delete');
				}
			},
			error: function(xhr, status, error) {
				alert('AJAX Error: ' + error + '\nStatus: ' + status);
				console.error('Delete file error:', xhr.responseText);
				$btn.prop('disabled', false).text('Delete');
			}
		});
	});
});
</script>
	<?php endif; ?>
