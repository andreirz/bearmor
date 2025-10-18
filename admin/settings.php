<?php
/**
 * Settings View
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Save settings
if ( isset( $_POST['bearmor_save_settings'] ) && check_admin_referer( 'bearmor_settings' ) ) {
	$settings = get_option( 'bearmor_settings', array() );
	$scan_schedule = sanitize_text_field( $_POST['scan_schedule'] );
	$settings['scan_schedule'] = $scan_schedule;
	$settings['notification_email'] = sanitize_email( $_POST['notification_email'] );
	$settings['auto_quarantine'] = isset( $_POST['auto_quarantine'] ) ? true : false;
	$settings['auto_disable_vulnerable'] = isset( $_POST['auto_disable_vulnerable'] ) ? true : false;
	$settings['firewall_enabled'] = isset( $_POST['firewall_enabled'] ) ? true : false;
	$settings['firewall_rate_limiting'] = isset( $_POST['firewall_rate_limiting'] ) ? true : false;
	$settings['firewall_rate_limit'] = isset( $_POST['firewall_rate_limit'] ) ? intval( $_POST['firewall_rate_limit'] ) : 100;
	$settings['firewall_country_blocking'] = isset( $_POST['firewall_country_blocking'] ) ? true : false;
	$settings['firewall_blocked_countries'] = sanitize_text_field( $_POST['firewall_blocked_countries'] );
	$settings['firewall_honeypot'] = isset( $_POST['firewall_honeypot'] ) ? true : false;
	update_option( 'bearmor_settings', $settings );
	
	// Update scan scheduler based on schedule setting
	if ( $scan_schedule === 'daily' ) {
		Bearmor_Scan_Scheduler::set_scan_enabled( 'malware', true );
	} else {
		Bearmor_Scan_Scheduler::set_scan_enabled( 'malware', false );
	}
	// Deep scans are always manual-only (no automatic scheduling)
	
	// Save scan exclusions
	if ( isset( $_POST['bearmor_scan_exclusions'] ) ) {
		Bearmor_Exclusions::set_patterns_text( $_POST['bearmor_scan_exclusions'] );
	}
	
	// Save 2FA settings
	update_option( 'bearmor_2fa_enabled', isset( $_POST['bearmor_2fa_enabled'] ) );
	
	// Save excluded users
	$excluded_users = array();
	if ( isset( $_POST['bearmor_2fa_users'] ) && is_array( $_POST['bearmor_2fa_users'] ) ) {
		$all_users = get_users( array( 'fields' => 'ID' ) );
		foreach ( $all_users as $user_id ) {
			if ( ! in_array( $user_id, $_POST['bearmor_2fa_users'] ) ) {
				$excluded_users[] = $user_id;
			}
		}
	}
	update_option( 'bearmor_2fa_excluded_users', $excluded_users );
	
	echo '<div class="notice notice-success"><p>Settings saved!</p></div>';
}

// Apply recommended hardening
if ( isset( $_POST['bearmor_apply_hardening'] ) && check_admin_referer( 'bearmor_settings' ) ) {
	// Placeholder for hardening actions (will be implemented in 1G)
	echo '<div class="notice notice-success"><p>Recommended hardening will be applied in future updates.</p></div>';
}

$settings = get_option( 'bearmor_settings', array() );
$license_info = Bearmor_License::get_info();
$site_id = get_option( 'bearmor_site_id' );

// Check license verification status for warning
$last_verified = $license_info['last_verified'];
$grace_period = $license_info['grace_period'];
$days_since_verified = 0;

if ( $last_verified ) {
	$days_since_verified = floor( ( time() - strtotime( $last_verified ) ) / DAY_IN_SECONDS );
}
?>

<div class="wrap">
	<h1>Bearmor Security Settings</h1>
	
	<?php
	// Show warning if license verification is failing
	if ( $days_since_verified >= 3 && $days_since_verified < $grace_period ) {
		?>
		<div class="notice notice-warning"><p>
			<strong>⚠️ License Verification Failing:</strong> 
			Last successful check was <?php echo esc_html( $days_since_verified ); ?> days ago. 
			The plugin will automatically retry. 
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings&action=refresh_license' ) ); ?>">Retry now</a>
		</p></div>
		<?php
	} elseif ( $days_since_verified >= $grace_period ) {
		?>
		<div class="notice notice-error"><p>
			<strong>❌ License Verification Failed:</strong> 
			No successful verification for <?php echo esc_html( $grace_period ); ?> days. 
			Pro features are disabled. Free features continue to work.
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings&action=refresh_license' ) ); ?>">Retry now</a>
		</p></div>
		<?php
	}
	?>
	
	<!-- License Info Block -->
	<div style="background: #fff; border: 1px solid #ccc; border-radius: 4px; padding: 20px; margin-bottom: 20px; max-width: 600px;">
		<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
			<div>
				<p style="margin: 0; font-size: 14px; color: #666;">Current Plan</p>
				<div style="display: flex; align-items: center; gap: 10px; margin-top: 5px;">
					<p style="margin: 0; font-size: 20px; font-weight: bold;"><?php echo esc_html( ucfirst( $license_info['plan'] ) ); ?></p>
					<?php
					$badge_color = $license_info['pro_enabled'] ? '#8269FF' : '#999';
					$badge_text = $license_info['pro_enabled'] ? 'PRO' : 'FREE';
					?>
					<span style="
						background: <?php echo esc_attr( $badge_color ); ?>;
						color: white;
						padding: 4px 10px;
						border-radius: 12px;
						font-size: 11px;
						font-weight: 600;
					">
						<?php echo esc_html( $badge_text ); ?>
					</span>
				</div>
			</div>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings&action=refresh_license' ) ); ?>" class="button button-secondary">Refresh</a>
		</div>
		
		<div style="border-top: 1px solid #eee; padding-top: 15px; font-size: 13px;">
			<p style="margin: 0;"><strong>Site ID:</strong> <code style="background: #f5f5f5; padding: 2px 4px;"><?php echo esc_html( $site_id ); ?></code></p>
			<?php if ( $license_info['expires'] ) : ?>
				<p style="margin: 8px 0 0 0;"><strong>Expires:</strong> <?php echo esc_html( $license_info['expires'] ); ?></p>
			<?php endif; ?>
			<p style="margin: 8px 0 0 0;"><strong>Last Verified:</strong> <?php echo $license_info['last_verified'] ? esc_html( $license_info['last_verified'] ) : 'Never'; ?></p>
			<p style="margin: 8px 0 0 0;"><strong>Paid Features:</strong> Deep Scan, Vulnerability Scanner, Firewall, AI Analysis, Uptime Monitoring</p>
			<p style="margin: 8px 0 0 0;"><a href="https://bearmor.com/support" target="_blank">Get Support</a> | <a href="https://bearmor.com/pricing" target="_blank">Upgrade Plan</a></p>
		</div>
	</div>
	
	<form method="post">
		<?php wp_nonce_field( 'bearmor_settings' ); ?>
		
		<table class="form-table">
			<tr>
				<th>Scan Schedule</th>
				<td>
					<select name="scan_schedule">
						<option value="manual" <?php selected( $settings['scan_schedule'], 'manual' ); ?>>Manual</option>
						<option value="daily" <?php selected( $settings['scan_schedule'], 'daily' ); ?>>Daily</option>
					</select>
					<p class="description">
						<strong>Manual:</strong> Run scans manually only<br>
						<em>Deep scans are manual-only (with batch processing to avoid slowdowns)</em>
					</p>
				</td>
			</tr>
			<tr>
				<th>Notification Email</th>
				<td>
					<input type="email" name="notification_email" value="<?php echo esc_attr( isset( $settings['notification_email'] ) ? $settings['notification_email'] : '' ); ?>" class="regular-text">
				</td>
			</tr>
		</table>

		<h2>Scan Exclusions</h2>
		<p class="description">Exclude files and folders from security scans. One pattern per line.</p>
		<table class="form-table">
			<tr>
				<th scope="row">
					<label for="bearmor_scan_exclusions">Exclusion Patterns</label>
				</th>
				<td>
					<textarea 
						id="bearmor_scan_exclusions" 
						name="bearmor_scan_exclusions" 
						rows="6" 
						cols="50"
						placeholder="node_modules/&#10;vendor/&#10;*.min.js&#10;wp-content/cache/"
					><?php echo esc_textarea( Bearmor_Exclusions::get_patterns_text() ); ?></textarea>
					<p class="description">
						<strong>Examples:</strong><br>
						<code>node_modules/</code> - Exclude directory<br>
						<code>*.min.js</code> - Exclude file pattern<br>
						<code>wp-backup-*</code> - Exclude with wildcard<br>
						<code>.git/</code> - Exclude .git folder
					</p>
				</td>
			</tr>
		</table>

		<h2>Automated Actions</h2>
		<p class="description">⚠️ Warning: These actions will execute automatically without confirmation.</p>
		<table class="form-table">
			<tr>
				<th>Auto-Quarantine Malware</th>
				<td>
					<label>
						<input type="checkbox" name="auto_quarantine" value="1" <?php checked( ! empty( $settings['auto_quarantine'] ) ); ?>>
						Automatically quarantine detected malware files
					</label>
				</td>
			</tr>
			<tr>
				<th>Auto-Disable Vulnerable Plugins</th>
				<td>
					<label>
						<input type="checkbox" name="auto_disable_vulnerable" value="1" <?php checked( ! empty( $settings['auto_disable_vulnerable'] ) ); ?>>
						Automatically disable plugins with critical vulnerabilities (Pro feature)
					</label>
				</td>
			</tr>
			<tr>
				<th>Web Application Firewall</th>
				<td>
					<label>
						<input type="checkbox" name="firewall_enabled" value="1" <?php checked( ! empty( $settings['firewall_enabled'] ) ); ?>>
						Enable firewall to block SQL injection, XSS, and other attacks
					</label>
					<p class="description">Protects your site from common web attacks. Enabled by default.</p>
				</td>
			</tr>
		</table>

		<h2>🔥 Advanced Firewall (Pro Features)</h2>
		<p class="description" style="background: #fff3cd; padding: 10px; border-left: 3px solid #ffc107; margin-bottom: 15px;">
			⭐ <strong>Pro Features:</strong> These advanced firewall features are available for testing. In production, they will require a Pro license.
		</p>
		<table class="form-table">
			<tr>
				<th>Rate Limiting</th>
				<td>
					<label>
						<input type="checkbox" name="firewall_rate_limiting" value="1" <?php checked( ! empty( $settings['firewall_rate_limiting'] ) ); ?>>
						Block IPs exceeding request limit
					</label>
					<p class="description">
						Limit: <input type="number" name="firewall_rate_limit" value="<?php echo esc_attr( isset( $settings['firewall_rate_limit'] ) ? $settings['firewall_rate_limit'] : 100 ); ?>" min="10" max="1000" style="width: 80px;"> requests per minute
					</p>
					<p class="description">Prevents DDoS attacks and aggressive bots. Recommended: 100 req/min.</p>
				</td>
			</tr>
			<tr>
				<th>Country Blocking</th>
				<td>
					<label>
						<input type="checkbox" name="firewall_country_blocking" value="1" <?php checked( ! empty( $settings['firewall_country_blocking'] ) ); ?>>
						Block requests from specific countries
					</label>
					<p class="description">
						Blocked countries (comma-separated codes): 
						<input type="text" name="firewall_blocked_countries" value="<?php echo esc_attr( isset( $settings['firewall_blocked_countries'] ) ? $settings['firewall_blocked_countries'] : '' ); ?>" placeholder="e.g., CN, RU, KP" style="width: 300px;">
					</p>
					<p class="description">Use 2-letter country codes (e.g., US, GB, CN). <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2" target="_blank">See full list</a></p>
				</td>
			</tr>
			<tr>
				<th>Honeypot Protection</th>
				<td>
					<label>
						<input type="checkbox" name="firewall_honeypot" value="1" <?php checked( ! empty( $settings['firewall_honeypot'] ) ); ?>>
						Add invisible honeypot fields to forms
					</label>
					<p class="description">Catches spam bots on login and comment forms. Invisible to real users.</p>
				</td>
			</tr>
		</table>

		<h2>🔐 Two-Factor Authentication (2FA)</h2>
		<p class="description">Add an extra layer of security by requiring a verification code sent to email after password login.</p>
		<table class="form-table">
			<tr>
				<th>Enable 2FA</th>
				<td>
					<label>
						<input type="checkbox" name="bearmor_2fa_enabled" value="1" <?php checked( get_option( 'bearmor_2fa_enabled', false ) ); ?> id="bearmor_2fa_toggle">
						Require two-factor authentication for all users
					</label>
					<p class="description">When enabled, users must enter a code sent to their email after logging in with their password.</p>
				</td>
			</tr>
		</table>

		<?php
		$is_2fa_enabled = get_option( 'bearmor_2fa_enabled', false );
		$excluded_users = get_option( 'bearmor_2fa_excluded_users', array() );
		?>

		<div id="bearmor_2fa_users_section" style="<?php echo $is_2fa_enabled ? '' : 'display:none;'; ?>">
			<h3>Users with 2FA</h3>
			<p class="description">Uncheck users to exclude them from 2FA requirement.</p>
			<table class="widefat striped">
				<thead>
					<tr>
						<th style="width: 50px;">Enabled</th>
						<th>Username</th>
						<th>Email</th>
						<th>Role</th>
					</tr>
				</thead>
				<tbody>
					<?php
					$users = get_users();
					foreach ( $users as $user ) :
						$is_excluded = in_array( $user->ID, $excluded_users );
					?>
						<tr>
							<td>
								<input type="checkbox" 
									   name="bearmor_2fa_users[]" 
									   value="<?php echo esc_attr( $user->ID ); ?>" 
									   <?php checked( ! $is_excluded ); ?>>
							</td>
							<td>
								<strong><?php echo esc_html( $user->user_login ); ?></strong>
								<?php if ( $user->ID === get_current_user_id() ) : ?>
									<span style="color: #666;">(you)</span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $user->user_email ); ?></td>
							<td><?php echo esc_html( implode( ', ', $user->roles ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<p class="description" style="margin-top: 10px;">
				<strong>Note:</strong> Users will need to enter a 6-digit code sent to their email after logging in. 
				Codes expire in 10 minutes. Users can choose to remember their device for 30 days.
			</p>
		</div>

		<script>
			document.getElementById('bearmor_2fa_toggle').addEventListener('change', function() {
				document.getElementById('bearmor_2fa_users_section').style.display = this.checked ? 'block' : 'none';
			});
		</script>

		<p>
			<button type="submit" name="bearmor_save_settings" class="button button-primary">Save & Apply</button>
			<button type="submit" name="bearmor_apply_hardening" class="button button-secondary" style="margin-left: 10px;">Apply Recommended Hardening</button>
		</p>
	</form>
</div>
