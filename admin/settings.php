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
	$settings['scan_schedule'] = sanitize_text_field( $_POST['scan_schedule'] );
	$settings['notification_email'] = sanitize_email( $_POST['notification_email'] );
	$settings['auto_quarantine'] = isset( $_POST['auto_quarantine'] ) ? true : false;
	$settings['auto_disable_vulnerable'] = isset( $_POST['auto_disable_vulnerable'] ) ? true : false;
	update_option( 'bearmor_settings', $settings );
	
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
?>

<div class="wrap">
	<h1>Bearmor Security Settings</h1>
	<form method="post">
		<?php wp_nonce_field( 'bearmor_settings' ); ?>
		
		<h2>General Settings</h2>
		<table class="form-table">
			<tr>
				<th>Scan Schedule</th>
				<td>
					<select name="scan_schedule">
						<option value="manual" <?php selected( $settings['scan_schedule'], 'manual' ); ?>>Manual</option>
						<option value="daily" <?php selected( $settings['scan_schedule'], 'daily' ); ?>>Daily</option>
						<option value="weekly" <?php selected( $settings['scan_schedule'], 'weekly' ); ?>>Weekly</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Notification Email</th>
				<td>
					<input type="email" name="notification_email" value="<?php echo esc_attr( $settings['notification_email'] ); ?>" class="regular-text">
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
