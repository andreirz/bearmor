<?php
/**
 * Hardening Admin Page
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$success_message = '';
$just_saved = false;

// Handle save
if ( isset( $_POST['bearmor_save_hardening'] ) && check_admin_referer( 'bearmor_hardening' ) ) {
	Bearmor_Hardening::save_settings( $_POST );
	$success_message = 'Settings saved successfully!';
	$just_saved = true;
}

// Handle quick actions
if ( isset( $_POST['bearmor_apply_recommended'] ) && check_admin_referer( 'bearmor_hardening_quick' ) ) {
	Bearmor_Hardening::apply_recommended();
	$success_message = 'Recommended hardening applied!';
	$just_saved = true;
}

if ( isset( $_POST['bearmor_disable_all'] ) && check_admin_referer( 'bearmor_hardening_quick' ) ) {
	Bearmor_Hardening::disable_all();
	$success_message = 'All hardening disabled!';
	$just_saved = true;
}

// Get status
$status = Bearmor_Hardening::get_hardening_status();

// Override file_editing_disabled with what user JUST clicked (if they just saved)
if ( $just_saved && isset( $_POST['bearmor_save_hardening'] ) ) {
	$status['file_editing_disabled'] = isset( $_POST['file_editing_disabled'] );
}

// Enqueue CSS
wp_enqueue_style( 'bearmor-dashboard', plugins_url( 'assets/css/dashboard.css', dirname( __FILE__ ) ), array(), '1.0.0' );
?>

<div class="wrap">
	<h1>Security Hardening</h1>

	<?php if ( $success_message ) : ?>
		<div class="notice notice-success is-dismissible">
			<p><strong>✅ <?php echo esc_html( $success_message ); ?></strong></p>
		</div>
	<?php endif; ?>

	<!-- Quick Actions -->
	<div style="background: #fff; border: 1px solid #ccc; padding: 20px; margin: 20px 0; border-radius: 5px;">
		<h2 style="margin-top: 0;">⚡ Quick Actions</h2>
		<form method="post" style="display: inline; margin-right: 10px;">
			<?php wp_nonce_field( 'bearmor_hardening_quick' ); ?>
			<button type="submit" name="bearmor_apply_recommended" value="1" class="button button-primary button-hero">
				✅ Apply Recommended
			</button>
		</form>
		<form method="post" style="display: inline;">
			<?php wp_nonce_field( 'bearmor_hardening_quick' ); ?>
			<button type="submit" name="bearmor_disable_all" value="1" class="button button-secondary" onclick="return confirm('Disable all hardening?');">
				🔓 Disable All
			</button>
		</form>
		<p style="margin: 10px 0 0 0; color: #666; font-size: 13px;">
			Enables all security headers and safe hardening options
		</p>
	</div>

	<form method="post">
		<?php wp_nonce_field( 'bearmor_hardening' ); ?>

		<!-- Hardening Options -->
		<div style="background: #fff; border: 1px solid #ccc; padding: 20px; margin: 20px 0; border-radius: 5px;">
			<h2 style="margin-top: 0;">⚙️ Hardening Options</h2>
			
			<table class="form-table">
				<tr>
					<th scope="row">Hide WordPress Version</th>
					<td>
						<label>
							<input type="checkbox" name="hide_wp_version" value="1" <?php checked( $status['hide_wp_version'] ); ?>>
							Removes version info from HTML
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">Block User Enumeration</th>
					<td>
						<label>
							<input type="checkbox" name="block_user_enum" value="1" <?php checked( $status['block_user_enum'] ); ?>>
							Prevents <code>?author=</code> queries from revealing usernames
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">Disable Verbose Login Errors</th>
					<td>
						<label>
							<input type="checkbox" name="disable_login_errors" value="1" <?php checked( $status['disable_login_errors'] ); ?>>
							Shows generic error instead of specific messages
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">Force SSL (HTTPS)</th>
					<td>
						<?php if ( $status['ssl_available'] ) : ?>
							<label>
								<input type="checkbox" name="force_ssl" value="1" <?php checked( $status['force_ssl'] ); ?>>
								Redirects all HTTP requests to HTTPS
							</label>
						<?php else : ?>
							<label>
								<input type="checkbox" disabled>
								Redirects all HTTP requests to HTTPS
								<span style="color: #d63638; font-size: 12px;"> (⚠️ SSL not detected)</span>
							</label>
						<?php endif; ?>
					</td>
				</tr>
				<tr style="background: #fff9e6;">
					<th scope="row">Disable XML-RPC</th>
					<td>
						<label>
							<input type="checkbox" name="disable_xmlrpc" value="1" <?php checked( $status['disable_xmlrpc'] ); ?>>
							Disables XML-RPC functionality
							<span style="color: #d63638; font-size: 12px;"> (⚠️ May break Jetpack, mobile apps)</span>
						</label>
					</td>
				</tr>
				<tr style="background: #fff9e6;">
					<th scope="row">Disable File Editing</th>
					<td>
						<label>
							<input type="checkbox" name="file_editing_disabled" value="1" <?php checked( $status['file_editing_disabled'] ); ?>>
							Prevents editing themes/plugins from WordPress admin
							<span style="color: #d63638; font-size: 12px;"> (⚠️ Modifies wp-config.php)</span>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">WP_DEBUG Status</th>
					<td>
						<label>
							<input type="checkbox" <?php checked( $status['debug_disabled'] ); ?> disabled>
							Debug mode disabled
							<?php if ( ! $status['debug_disabled'] ) : ?>
								<span style="color: #d63638; font-size: 12px;"> (⚠️ Currently enabled - edit wp-config.php manually)</span>
							<?php else : ?>
								<span style="color: #00a32a; font-size: 12px;"> (✅ Disabled)</span>
							<?php endif; ?>
						</label>
					</td>
				</tr>
			</table>
		</div>

		<!-- Security Headers -->
		<div style="background: #fff; border: 1px solid #ccc; padding: 20px; margin: 20px 0; border-radius: 5px;">
			<h2 style="margin-top: 0;">🔒 Security Headers</h2>
			<p style="color: #666; margin-bottom: 15px;">HTTP headers that protect against common attacks. All enabled by default.</p>
			
			<table class="form-table">
				<tr>
					<th scope="row">X-Frame-Options</th>
					<td>
						<label>
							<input type="checkbox" name="header_x_frame" value="1" <?php checked( $status['header_x_frame'] ); ?>>
							Prevents clickjacking attacks (blocks iframe embedding)
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">X-Content-Type-Options</th>
					<td>
						<label>
							<input type="checkbox" name="header_content_type" value="1" <?php checked( $status['header_content_type'] ); ?>>
							Prevents MIME-type sniffing
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">Referrer-Policy</th>
					<td>
						<label>
							<input type="checkbox" name="header_referrer" value="1" <?php checked( $status['header_referrer'] ); ?>>
							Controls referrer information
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">Permissions-Policy</th>
					<td>
						<label>
							<input type="checkbox" name="header_permissions" value="1" <?php checked( $status['header_permissions'] ); ?>>
							Blocks camera/microphone access
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">X-XSS-Protection</th>
					<td>
						<label>
							<input type="checkbox" name="header_xss" value="1" <?php checked( $status['header_xss'] ); ?>>
							Legacy XSS protection
						</label>
					</td>
				</tr>
			</table>
		</div>

		<p class="submit">
			<button type="submit" name="bearmor_save_hardening" value="1" class="button button-primary button-large">
				💾 Save All Settings
			</button>
		</p>
	</form>
</div>
