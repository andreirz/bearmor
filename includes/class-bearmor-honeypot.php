<?php
/**
 * Honeypot Class
 * Add invisible honeypot fields to forms to catch bots
 *
 * @package Bearmor_Security
 */

class Bearmor_Honeypot {

	/**
	 * Initialize honeypot
	 */
	public static function init() {
		// Check if honeypot is enabled
		$settings = get_option( 'bearmor_settings', array() );
		if ( empty( $settings['firewall_honeypot'] ) ) {
			return;
		}

		// Add honeypot to comment form
		add_action( 'comment_form_after_fields', array( __CLASS__, 'add_honeypot_field' ) );
		add_action( 'comment_form_logged_in_after', array( __CLASS__, 'add_honeypot_field' ) );
		
		// Check honeypot on comment submission
		add_filter( 'preprocess_comment', array( __CLASS__, 'check_comment_honeypot' ) );
		
		// Add honeypot to login form
		add_action( 'login_form', array( __CLASS__, 'add_honeypot_field' ) );
		add_filter( 'authenticate', array( __CLASS__, 'check_login_honeypot' ), 1, 3 ); // Priority 1 = very early
	}

	/**
	 * Add honeypot field to form
	 */
	public static function add_honeypot_field() {
		?>
		<div style="position: absolute; left: -9999px; width: 1px; height: 1px; overflow: hidden;">
			<label for="bearmor_website">Website (leave blank)</label>
			<input type="text" name="bearmor_website" id="bearmor_website" value="" tabindex="-1" autocomplete="off">
		</div>
		<?php
	}

	/**
	 * Check honeypot on comment submission
	 */
	public static function check_comment_honeypot( $commentdata ) {
		if ( ! empty( $_POST['bearmor_website'] ) ) {
			// Honeypot filled - it's a bot!
			wp_die( 
				'<h1>Spam Detected</h1><p>Your submission was identified as spam.</p>',
				'Spam Detected',
				array( 'response' => 403 )
			);
		}
		return $commentdata;
	}

	/**
	 * Check honeypot on login
	 */
	public static function check_login_honeypot( $user, $username, $password ) {
		// Only check if this is a POST request
		if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
			return $user;
		}

		// Only check if this is a login attempt (not empty username/password)
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		// Check if honeypot field was filled
		if ( isset( $_POST['bearmor_website'] ) && $_POST['bearmor_website'] !== '' ) {
			
			// Honeypot filled - it's a bot!
			// Log to activity log
			if ( class_exists( 'Bearmor_Activity_Log' ) ) {
				Bearmor_Activity_Log::log( 
					'login_blocked_honeypot', 
					'security', 
					'Honeypot triggered on login form (Username: ' . sanitize_text_field( $username ) . ')', 
					0 // System action
				);
			}
			
			// Die immediately with generic error (stronger than WP_Error)
			wp_die( 
				'<strong>Error:</strong> Invalid username or password.',
				'Login Failed',
				array( 'response' => 403, 'back_link' => true )
			);
		}
		
		return $user;
	}
}
