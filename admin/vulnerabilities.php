<?php
/**
 * Vulnerabilities Admin Page
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if Pro feature is available
$is_pro = Bearmor_License::is_pro();

// Handle manual scan
if ( isset( $_POST['bearmor_scan_vulnerabilities'] ) && check_admin_referer( 'bearmor_scan_vulnerabilities' ) ) {
	Bearmor_Vulnerability_Scanner::scan_all( true ); // Force refresh, skip cache
	echo '<div class="notice notice-success"><p>✅ Vulnerability scan completed!</p></div>';
}



// Get filter
$severity_filter = isset( $_GET['severity'] ) ? sanitize_text_field( $_GET['severity'] ) : '';

// Get vulnerabilities
$args = array( 'status' => 'active' );
if ( $severity_filter ) {
	$args['severity'] = $severity_filter;
}

$vulnerabilities = Bearmor_Vulnerability_Scanner::get_vulnerabilities( $args );
$counts = Bearmor_Vulnerability_Scanner::get_count_by_severity();
$last_scan = Bearmor_Vulnerability_Scanner::get_last_scan_time();

// Group vulnerabilities by plugin/theme
$grouped = array();
foreach ( $vulnerabilities as $vuln ) {
	$key = $vuln->item_slug;
	if ( ! isset( $grouped[ $key ] ) ) {
		$grouped[ $key ] = array(
			'item_name'    => $vuln->item_name,
			'item_version' => $vuln->item_version,
			'item_type'    => $vuln->item_type,
			'item_slug'    => $vuln->item_slug,
			'max_severity' => $vuln->severity,
			'vulns'        => array(),
		);
	}
	$grouped[ $key ]['vulns'][] = $vuln;
	
	// Track highest severity
	$severity_order = array( 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1 );
	if ( $severity_order[ $vuln->severity ] > $severity_order[ $grouped[ $key ]['max_severity'] ] ) {
		$grouped[ $key ]['max_severity'] = $vuln->severity;
	}
}

// Enqueue CSS
wp_enqueue_style( 'bearmor-dashboard', plugins_url( 'assets/css/dashboard.css', dirname( __FILE__ ) ), array(), '1.0.0' );
?>

<div class="wrap">
	<h1>Vulnerabilities</h1>

	<?php if ( ! $is_pro ) : ?>
		<!-- Pro Feature Overlay -->
		<div style="
			background: #f5f5f5;
			border: 2px solid #ddd;
			border-radius: 8px;
			padding: 40px;
			text-align: center;
			margin: 20px 0;
		">
			<h2 style="color: #666; margin-top: 0;">🔒 Pro Feature</h2>
			<p style="color: #999; font-size: 16px; margin: 10px 0;">
				Vulnerability Scanner is available for Pro members only.
			</p>
			<p style="color: #999; margin: 20px 0;">
				Check your plugins and themes against the WPScan vulnerability database to identify security issues before they become a problem.
			</p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="button button-primary" style="background: #8269FF; border-color: #8269FF;">
				Upgrade to Pro
			</a>
		</div>
	<?php endif; ?>

	<?php if ( ! $is_pro ) : ?>
	<!-- Example Preview (grayed out) -->
	<div style="opacity: 0.5; filter: grayscale(100%); margin-top: 30px;">
		<h3 style="color: #999;">Example Vulnerabilities:</h3>
		<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0;">
			<div style="background: #fff; border-left: 4px solid #d63638; padding: 20px; border-radius: 5px;">
				<h3 style="margin: 0; font-size: 32px; color: #d63638;">2</h3>
				<p style="margin: 5px 0 0 0; color: #666;">Critical</p>
			</div>
			<div style="background: #fff; border-left: 4px solid #f56e28; padding: 20px; border-radius: 5px;">
				<h3 style="margin: 0; font-size: 32px; color: #f56e28;">1</h3>
				<p style="margin: 5px 0 0 0; color: #666;">High</p>
			</div>
		</div>

		<table class="wp-list-table widefat fixed striped" style="font-size: 12px;">
			<thead>
				<tr>
					<th>Plugin/Theme</th>
					<th style="width: 80px;">Severity</th>
					<th>Vulnerability</th>
					<th style="width: 100px;">Fixed In</th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td>
						<strong>WooCommerce</strong><br>
						<small style="color: #999;">plugin</small>
					</td>
					<td>
						<span style="background: #d63638; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">
							Critical
						</span>
					</td>
					<td>Unauthenticated SQL Injection</td>
					<td><code style="background: #f5f5f5; padding: 2px 4px;">v7.2.0</code></td>
				</tr>
				<tr>
					<td>
						<strong>Elementor</strong><br>
						<small style="color: #999;">plugin</small>
					</td>
					<td>
						<span style="background: #f56e28; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">
							High
						</span>
					</td>
					<td>Stored XSS in Page Builder</td>
					<td><code style="background: #f5f5f5; padding: 2px 4px;">v3.15.0</code></td>
				</tr>
			</tbody>
		</table>
		<p style="text-align: center; color: #999; font-size: 11px; margin-top: 10px;">
			<em>Demo data - This is what you'll see with Pro</em>
		</p>
	</div>
	<?php endif; ?>

	<?php if ( $is_pro ) : ?>
	<!-- Stats Cards -->
	<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0;">
		<div style="background: #fff; border-left: 4px solid #d63638; padding: 20px; border-radius: 5px;">
			<h3 style="margin: 0; font-size: 32px; color: #d63638;"><?php echo $counts['critical']; ?></h3>
			<p style="margin: 5px 0 0 0; color: #666;">Critical</p>
		</div>
		<div style="background: #fff; border-left: 4px solid #f56e28; padding: 20px; border-radius: 5px;">
			<h3 style="margin: 0; font-size: 32px; color: #f56e28;"><?php echo $counts['high']; ?></h3>
			<p style="margin: 5px 0 0 0; color: #666;">High</p>
		</div>
		<div style="background: #fff; border-left: 4px solid #dba617; padding: 20px; border-radius: 5px;">
			<h3 style="margin: 0; font-size: 32px; color: #dba617;"><?php echo $counts['medium']; ?></h3>
			<p style="margin: 5px 0 0 0; color: #666;">Medium</p>
		</div>
		<div style="background: #fff; border-left: 4px solid #00a32a; padding: 20px; border-radius: 5px;">
			<h3 style="margin: 0; font-size: 32px; color: #00a32a;"><?php echo $counts['low']; ?></h3>
			<p style="margin: 5px 0 0 0; color: #666;">Low</p>
		</div>
	</div>

	<!-- Scan Button -->
	<div style="background: #fff; border: 1px solid #ccc; padding: 15px; margin: 20px 0; border-radius: 5px; display: flex; justify-content: space-between; align-items: center;">
		<div>
			<?php if ( $last_scan ) : ?>
				<p style="margin: 0;">
					<strong>Last Scan:</strong> <?php echo esc_html( date( 'Y-m-d H:i:s', strtotime( $last_scan ) ) ); ?>
				</p>
			<?php else : ?>
				<p style="margin: 0; color: #d63638;">
					<strong>⚠️ No scan performed yet</strong>
				</p>
			<?php endif; ?>
		</div>
		<form method="post">
			<?php wp_nonce_field( 'bearmor_scan_vulnerabilities' ); ?>
			<button type="submit" name="bearmor_scan_vulnerabilities" class="button button-primary">
				🔍 Scan Now
			</button>
		</form>
	</div>

	<!-- Filters -->
	<div style="background: #fff; border: 1px solid #ccc; padding: 15px; margin: 20px 0; border-radius: 5px;">
		<form method="get" style="display: flex; gap: 10px; align-items: center;">
			<input type="hidden" name="page" value="bearmor-vulnerabilities">
			
			<label><strong>Filter by Severity:</strong></label>
			<select name="severity" style="min-width: 150px;">
				<option value="">All Severities</option>
				<option value="critical" <?php selected( $severity_filter, 'critical' ); ?>>🔴 Critical</option>
				<option value="high" <?php selected( $severity_filter, 'high' ); ?>>🟠 High</option>
				<option value="medium" <?php selected( $severity_filter, 'medium' ); ?>>🟡 Medium</option>
				<option value="low" <?php selected( $severity_filter, 'low' ); ?>>🟢 Low</option>
			</select>
			
			<button type="submit" class="button">Filter</button>
			
			<?php if ( $severity_filter ) : ?>
				<a href="<?php echo admin_url( 'admin.php?page=bearmor-vulnerabilities' ); ?>" class="button">Clear</a>
			<?php endif; ?>
		</form>
	</div>

	<!-- Vulnerabilities List -->
	<?php if ( empty( $grouped ) ) : ?>
		<div style="background: #d7f7e8; border: 1px solid #00a32a; padding: 30px; text-align: center; border-radius: 5px;">
			<h2 style="margin: 0; color: #00a32a;">✅ No Vulnerabilities Found!</h2>
			<p style="margin: 10px 0 0 0; color: #666;">Your plugins and themes are secure.</p>
		</div>
	<?php else : ?>
		<div style="background: #fff; border: 1px solid #ccc; border-radius: 5px; overflow: hidden;">
			<?php foreach ( $grouped as $item ) : ?>
				<?php $vuln_count = count( $item['vulns'] ); ?>
				<div style="border-bottom: 1px solid #eee; padding: 20px;">
					<!-- Plugin/Theme Header -->
					<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
						<div style="flex: 1;">
							<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
								<span style="background: <?php echo Bearmor_WPVulnerability_API::get_severity_color( $item['max_severity'] ); ?>; color: white; padding: 4px 12px; border-radius: 3px; font-size: 12px; font-weight: bold;">
									<?php echo esc_html( Bearmor_WPVulnerability_API::get_severity_label( $item['max_severity'] ) ); ?>
								</span>
								<span style="background: #f0f0f0; padding: 4px 12px; border-radius: 3px; font-size: 12px;">
									<?php echo esc_html( ucfirst( $item['item_type'] ) ); ?>
								</span>
								<span style="background: #d63638; color: white; padding: 4px 12px; border-radius: 3px; font-size: 12px; font-weight: bold;">
									<?php echo $vuln_count; ?> Vulnerabilit<?php echo $vuln_count > 1 ? 'ies' : 'y'; ?>
								</span>
							</div>
							
							<h3 style="margin: 0 0 5px 0; font-size: 20px;">
								<?php echo esc_html( $item['item_name'] ); ?> 
								<span style="color: #666; font-weight: normal; font-size: 16px;">
									(v<?php echo esc_html( $item['item_version'] ); ?>)
								</span>
							</h3>
						</div>
						
						<!-- Actions -->
						<div style="display: flex; flex-direction: column; gap: 8px; margin-left: 20px;">
							<a href="<?php echo admin_url( 'plugins.php' ); ?>" class="button button-primary">
								⬆️ Update Now
							</a>

</form>
							<a href="<?php echo admin_url( 'plugins.php' ); ?>" class="button button-secondary">
								🚫 Disable Plugin
							</a>
						</div>
					</div>
					
					<!-- Individual Vulnerabilities -->
					<div style="background: #f9f9f9; padding: 15px; border-radius: 5px;">
						<?php foreach ( $item['vulns'] as $vuln ) : ?>
							<?php 
							// Strip [en] tags and HTML
							$description = wp_strip_all_tags( $vuln->description );
							$description = preg_replace( '/^\[en\]\s*/i', '', $description );
							$description = trim( $description );
							$is_long = strlen( $description ) > 200;
							$short_desc = $is_long ? substr( $description, 0, 200 ) . '...' : $description;
							?>
							<div style="margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #ddd;">
								<p style="margin: 0 0 8px 0; font-size: 15px; font-weight: 600; color: #d63638;">
									<?php echo esc_html( $vuln->title ); ?>
								</p>
								
								<?php if ( $description ) : ?>
									<p style="margin: 0 0 8px 0; color: #666; font-size: 13px; line-height: 1.5;">
										<span class="vuln-desc-short-<?php echo $vuln->id; ?>">
											<?php echo esc_html( $short_desc ); ?>
										</span>
										<?php if ( $is_long ) : ?>
											<span class="vuln-desc-full-<?php echo $vuln->id; ?>" style="display: none;">
												<?php echo esc_html( $description ); ?>
											</span>
											<a href="#" onclick="event.preventDefault(); document.querySelector('.vuln-desc-short-<?php echo $vuln->id; ?>').style.display='none'; document.querySelector('.vuln-desc-full-<?php echo $vuln->id; ?>').style.display='inline'; this.style.display='none'; document.querySelector('.vuln-less-<?php echo $vuln->id; ?>').style.display='inline';" style="color: #2271b1; text-decoration: none; font-size: 12px;">
												View more
											</a>
											<a href="#" class="vuln-less-<?php echo $vuln->id; ?>" onclick="event.preventDefault(); document.querySelector('.vuln-desc-short-<?php echo $vuln->id; ?>').style.display='inline'; document.querySelector('.vuln-desc-full-<?php echo $vuln->id; ?>').style.display='none'; this.style.display='none'; this.previousElementSibling.style.display='inline';" style="display: none; color: #2271b1; text-decoration: none; font-size: 12px;">
												View less
											</a>
										<?php endif; ?>
									</p>
								<?php endif; ?>
								
								<div style="display: flex; gap: 15px; font-size: 12px; color: #666;">
									<?php if ( $vuln->fixed_in ) : ?>
										<span>
											<strong>Fixed in:</strong> 
											<code style="background: #fff; padding: 2px 6px; border-radius: 3px;">
												v<?php echo esc_html( $vuln->fixed_in ); ?>
											</code>
										</span>
									<?php endif; ?>
									
									<?php if ( $vuln->cve_references ) : ?>
										<span>
											<strong>CVE:</strong> <?php echo esc_html( $vuln->cve_references ); ?>
										</span>
									<?php endif; ?>
								</div>
							</div>
						<?php endforeach; ?>
					</div>
				</div>
			<?php endforeach; ?>
		</div>
	<?php endif; ?>

	<!-- Info Box -->
	<div style="background: #f0f6fc; border: 1px solid #c3e0f7; padding: 15px; margin: 20px 0; border-radius: 5px;">
		<h3 style="margin-top: 0;">ℹ️ About Vulnerability Scanner</h3>
		<ul style="margin: 0; padding-left: 20px;">
			<li>Scans active plugins and themes against <strong>WPVulnerability.net</strong> database</li>
			<li>Automatically scans <strong>once per day</strong></li>
			<li>Results are cached for <strong>24 hours</strong> to reduce API calls</li>
			<li>Update vulnerable plugins/themes immediately to stay secure</li>
			<li>Whitelist false positives to hide them from the list</li>
		</ul>
	</div>
</div>
	<?php endif; ?>
