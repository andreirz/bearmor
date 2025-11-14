<?php
/**
 * Two-Factor Authentication Class
 *
 * @package Bearmor_Security
 */

class Bearmor_2FA {

	/**
	 * Initialize hooks
	 */
	public static function init() {
		// Hook into login process
		add_filter( 'authenticate', array( __CLASS__, 'check_2fa_requirement' ), 30, 3 );
		add_action( 'login_form', array( __CLASS__, 'maybe_show_2fa_form' ) );
		add_action( 'login_enqueue_scripts', array( __CLASS__, 'enqueue_login_styles' ) );
		
		// Handle 2FA verification
		add_action( 'init', array( __CLASS__, 'handle_2fa_verification' ) );
		
		// Remember device cookie
		add_action( 'wp_login', array( __CLASS__, 'maybe_set_remember_cookie' ), 10, 2 );
	}

	/**
	 * Check if 2FA is enabled globally
	 */
	public static function is_2fa_enabled() {
		return (bool) get_option( 'bearmor_2fa_enabled', false );
	}

	/**
	 * Check if 2FA is required for a specific user
	 */
	public static function is_2fa_required_for_user( $user_id ) {
		if ( ! self::is_2fa_enabled() ) {
			return false;
		}
		
		// Check if user is excluded
		$excluded_users = get_option( 'bearmor_2fa_excluded_users', array() );
		return ! in_array( $user_id, $excluded_users );
	}

	/**
	 * Check if device is remembered
	 */
	public static function is_device_remembered( $user_id ) {
		$cookie_name = 'bearmor_2fa_remember_' . $user_id;
		
		if ( ! isset( $_COOKIE[ $cookie_name ] ) ) {
			return false;
		}
		
		$stored_token = get_user_meta( $user_id, 'bearmor_2fa_remember_token', true );
		return $stored_token && hash_equals( $stored_token, $_COOKIE[ $cookie_name ] );
	}

	/**
	 * Generate 6-digit code
	 */
	public static function generate_code() {
		return str_pad( wp_rand( 0, 999999 ), 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Send 2FA code via email
	 */
	public static function send_code( $user_id, $code ) {
		$user = get_userdata( $user_id );
		
		if ( ! $user ) {
			return false;
		}
		
		$to = $user->user_email;
		$subject = '🔐 Your Login Verification Code';
		
		$message = "Hello {$user->display_name},\n\n";
		$message .= "Someone is trying to log in to your account on " . get_bloginfo( 'name' ) . ".\n\n";
		$message .= "Your verification code is:\n\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
		$message .= "        {$code}\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
		$message .= "This code will expire in 10 minutes.\n\n";
		$message .= "If you didn't try to log in, please ignore this email and change your password immediately.\n\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
		$message .= "Protected by Bearmor Security Plugin\n";
		$message .= get_site_url() . "\n";
		
		$headers = array(
			'From: ' . get_bloginfo( 'name' ) . ' <' . get_option( 'admin_email' ) . '>',
		);
		
		return wp_mail( $to, $subject, $message, $headers );
	}

	/**
	 * Check 2FA requirement during authentication
	 */
	public static function check_2fa_requirement( $user, $username, $password ) {
		// Skip if already an error
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		
		// Skip if not a user object
		if ( ! $user instanceof WP_User ) {
			return $user;
		}
		
		// Check if 2FA is required for this user
		if ( ! self::is_2fa_required_for_user( $user->ID ) ) {
			return $user;
		}
		
		// Check if device is remembered
		if ( self::is_device_remembered( $user->ID ) ) {
			return $user;
		}
		
		// Check if we're verifying 2FA code
		if ( isset( $_POST['bearmor_2fa_verify'] ) ) {
			return $user; // Let verification handler deal with it
		}
		
		// Generate and send code
		$code = self::generate_code();
		set_transient( 'bearmor_2fa_code_' . $user->ID, $code, 600 ); // 10 minutes
		set_transient( 'bearmor_2fa_user_' . $user->ID, $user->ID, 600 );
		
		self::send_code( $user->ID, $code );
		
		// Return error to stop login and show 2FA form
		return new WP_Error( 'bearmor_2fa_required', '2FA verification required' );
	}

	/**
	 * Handle 2FA verification
	 */
	public static function handle_2fa_verification() {
		if ( ! isset( $_POST['bearmor_2fa_verify'] ) || ! isset( $_POST['bearmor_2fa_code'] ) ) {
			return;
		}
		
		if ( ! isset( $_POST['bearmor_2fa_nonce'] ) || ! wp_verify_nonce( $_POST['bearmor_2fa_nonce'], 'bearmor_2fa_verify' ) ) {
			return;
		}
		
		$user_id = isset( $_POST['bearmor_2fa_user'] ) ? intval( $_POST['bearmor_2fa_user'] ) : 0;
		$entered_code = sanitize_text_field( $_POST['bearmor_2fa_code'] );
		
		if ( ! $user_id ) {
			return;
		}
		
		$stored_code = get_transient( 'bearmor_2fa_code_' . $user_id );
		
		if ( ! $stored_code ) {
			wp_safe_redirect( wp_login_url() . '?bearmor_2fa_error=expired' );
			exit;
		}
		
		if ( $entered_code !== $stored_code ) {
			wp_safe_redirect( wp_login_url() . '?bearmor_2fa_error=invalid&user_id=' . $user_id );
			exit;
		}
		
		// Code is valid - delete transients
		delete_transient( 'bearmor_2fa_code_' . $user_id );
		delete_transient( 'bearmor_2fa_user_' . $user_id );
		
		// Log user in
		wp_set_auth_cookie( $user_id, true );
		
		// Set remember cookie if requested
		if ( isset( $_POST['bearmor_2fa_remember'] ) ) {
			self::set_remember_cookie( $user_id );
		}
		
		// Redirect to admin
		wp_safe_redirect( admin_url() );
		exit;
	}

	/**
	 * Set remember device cookie
	 */
	public static function set_remember_cookie( $user_id ) {
		$token = wp_generate_password( 32, false );
		$cookie_name = 'bearmor_2fa_remember_' . $user_id;
		
		// Store token in user meta
		update_user_meta( $user_id, 'bearmor_2fa_remember_token', $token );
		
		// Set cookie for 30 days
		setcookie( $cookie_name, $token, time() + ( 30 * DAY_IN_SECONDS ), COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
	}

	/**
	 * Maybe set remember cookie after login
	 */
	public static function maybe_set_remember_cookie( $user_login, $user ) {
		// This is called after successful login, but we handle remember in verification
		// Keeping this hook for future use
	}

	/**
	 * Show 2FA form on login page
	 */
	public static function maybe_show_2fa_form() {
		// Check if we need to show 2FA form
		$user_id = 0;
		
		// Check for user_id in URL (from failed verification)
		if ( isset( $_GET['user_id'] ) ) {
			$user_id = intval( $_GET['user_id'] );
		}
		
		// Check for active 2FA session
		if ( ! $user_id && isset( $_COOKIE['bearmor_2fa_pending'] ) ) {
			$user_id = intval( $_COOKIE['bearmor_2fa_pending'] );
		}
		
		// Check transient
		foreach ( array_keys( $_COOKIE ) as $key ) {
			if ( strpos( $key, 'bearmor_2fa_user_' ) === 0 ) {
				$uid = str_replace( 'bearmor_2fa_user_', '', $key );
				if ( get_transient( 'bearmor_2fa_code_' . $uid ) ) {
					$user_id = $uid;
					break;
				}
			}
		}
		
		if ( ! $user_id || ! get_transient( 'bearmor_2fa_code_' . $user_id ) ) {
			return;
		}
		
		// Show 2FA form
		?>
		<style>
			#loginform { display: none; }
			.bearmor-2fa-form { text-align: center; }
			.bearmor-2fa-code-input { 
				font-size: 24px; 
				letter-spacing: 10px; 
				text-align: center; 
				width: 100%; 
				padding: 10px;
				margin: 20px 0;
			}
			.bearmor-2fa-error { 
				background: #dc3232; 
				color: white; 
				padding: 10px; 
				margin: 10px 0; 
				border-radius: 3px;
			}
			.bearmor-2fa-info {
				background: #72aee6;
				color: white;
				padding: 10px;
				margin: 10px 0;
				border-radius: 3px;
			}
		</style>
		
		<div class="bearmor-2fa-form">
			<h2>🔐 Two-Factor Authentication</h2>
			
			<?php if ( isset( $_GET['bearmor_2fa_error'] ) ) : ?>
				<?php if ( $_GET['bearmor_2fa_error'] === 'expired' ) : ?>
					<div class="bearmor-2fa-error">
						⏰ Your verification code has expired. Please log in again.
					</div>
				<?php elseif ( $_GET['bearmor_2fa_error'] === 'invalid' ) : ?>
					<div class="bearmor-2fa-error">
						❌ Invalid verification code. Please try again.
					</div>
				<?php endif; ?>
			<?php else : ?>
				<div class="bearmor-2fa-info">
					📧 A verification code has been sent to your email.
				</div>
			<?php endif; ?>
			
			<form method="post" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>">
				<?php wp_nonce_field( 'bearmor_2fa_verify', 'bearmor_2fa_nonce' ); ?>
				<input type="hidden" name="bearmor_2fa_verify" value="1">
				<input type="hidden" name="bearmor_2fa_user" value="<?php echo esc_attr( $user_id ); ?>">
				
				<p>
					<label for="bearmor_2fa_code">Enter the 6-digit code:</label>
					<input type="text" 
						   name="bearmor_2fa_code" 
						   id="bearmor_2fa_code" 
						   class="bearmor-2fa-code-input" 
						   maxlength="6" 
						   pattern="[0-9]{6}"
						   autocomplete="off"
						   autofocus
						   required>
				</p>
				
				<p>
					<label>
						<input type="checkbox" name="bearmor_2fa_remember" value="1">
						Remember this device for 30 days
					</label>
				</p>
				
				<p>
					<button type="submit" class="button button-primary button-large">Verify Code</button>
				</p>
				
				<p style="margin-top: 20px; font-size: 12px; color: #666;">
					Code expires in 10 minutes<br>
					Didn't receive it? <a href="<?php echo wp_login_url(); ?>">Try logging in again</a>
				</p>
			</form>
		</div>
		
		<script>
			// Auto-submit when 6 digits entered
			document.getElementById('bearmor_2fa_code').addEventListener('input', function(e) {
				if (this.value.length === 6) {
					this.form.submit();
				}
			});
		</script>
		<?php
	}

	/**
	 * Enqueue login page styles
	 */
	public static function enqueue_login_styles() {
		// Styles are inline in maybe_show_2fa_form()
	}

}
