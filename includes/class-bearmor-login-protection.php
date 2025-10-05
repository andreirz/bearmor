<?php
/**
 * Login Protection Class
 *
 * Handles brute-force protection and login attempt tracking
 *
 * @package Bearmor_Security
 */

class Bearmor_Login_Protection {

	/**
	 * Rate limit thresholds
	 */
	const LOCKOUT_5_MIN = 5;    // 5 failed attempts
	const LOCKOUT_30_MIN = 10;  // 10 failed attempts
	const LOCKOUT_24_HOUR = 20; // 20 failed attempts

	/**
	 * Initialize hooks
	 */
	public static function init() {
		// Check if IP is blocked VERY EARLY - before any authentication
		add_action( 'login_init', array( __CLASS__, 'block_login_if_ip_blocked' ) );
		
		// Track login attempts
		add_action( 'wp_login_failed', array( __CLASS__, 'log_failed_attempt' ) );
		add_action( 'wp_login', array( __CLASS__, 'log_successful_attempt' ), 10, 2 );
		
		// Clean up expired blocks
		add_action( 'bearmor_cleanup_expired_blocks', array( __CLASS__, 'cleanup_expired_blocks' ) );
		
		// Schedule cleanup if not already scheduled
		if ( ! wp_next_scheduled( 'bearmor_cleanup_expired_blocks' ) ) {
			wp_schedule_event( time(), 'hourly', 'bearmor_cleanup_expired_blocks' );
		}
	}

	/**
	 * Block login page if IP is blocked
	 */
	public static function block_login_if_ip_blocked() {
		// Only run on login page
		if ( ! isset( $_SERVER['REQUEST_URI'] ) || strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) === false ) {
			return;
		}

		$ip = self::get_client_ip();
		
		// Check if IP is whitelisted
		if ( self::is_ip_whitelisted( $ip ) ) {
			return;
		}

		// Check if IP is blocked
		$block = self::get_ip_block( $ip );
		
		if ( $block ) {
			// Check if permanent block
			if ( $block->permanent ) {
				wp_die(
					'<h1>Access Denied</h1><p>Your IP address has been permanently blocked due to suspicious activity.</p>',
					'IP Blocked',
					array( 'response' => 403 )
				);
			}
			
			// Check if temporary block expired
			if ( $block->expires_at && strtotime( $block->expires_at ) > current_time( 'timestamp' ) ) {
				$time_remaining = human_time_diff( current_time( 'timestamp' ), strtotime( $block->expires_at ) );
				wp_die(
					'<h1>Too Many Failed Login Attempts</h1><p>Please try again in ' . esc_html( $time_remaining ) . '.</p>',
					'Login Blocked',
					array( 'response' => 429 )
				);
			} else {
				// Block expired, remove it and clear failed attempts
				self::unblock_ip( $ip );
				self::clear_failed_attempts( $ip );
			}
		}
	}

	/**
	 * Log failed login attempt
	 *
	 * @param string $username Username used in failed attempt.
	 */
	public static function log_failed_attempt( $username ) {
		$ip = self::get_client_ip();
		
		// Don't track whitelisted IPs
		if ( self::is_ip_whitelisted( $ip ) ) {
			return;
		}

		// Get username from POST if not provided
		if ( empty( $username ) && isset( $_POST['log'] ) ) {
			$username = sanitize_user( $_POST['log'] );
		}

		// Log the attempt
		self::log_attempt( $ip, $username, false );

		// Check if we need to block this IP
		$failed_count = self::get_failed_attempts_count( $ip );

		if ( $failed_count >= self::LOCKOUT_24_HOUR ) {
			// 24 hour lockout
			self::block_ip( $ip, '24 hours', 'Too many failed login attempts (20+)' );
			// Send email notification for 24-hour ban
			self::send_lockout_notification( $ip, $username, $failed_count );
		} elseif ( $failed_count >= self::LOCKOUT_30_MIN ) {
			// 30 minute lockout
			self::block_ip( $ip, '30 minutes', 'Too many failed login attempts (10+)' );
		} elseif ( $failed_count >= self::LOCKOUT_5_MIN ) {
			// 5 minute lockout
			self::block_ip( $ip, '5 minutes', 'Too many failed login attempts (5+)' );
		}
	}

	/**
	 * Log successful login attempt
	 *
	 * @param string  $username Username.
	 * @param WP_User $user User object.
	 */
	public static function log_successful_attempt( $username, $user ) {
		$ip = self::get_client_ip();
		self::log_attempt( $ip, $username, true );
		
		// Clear failed attempts for this IP on successful login
		self::clear_failed_attempts( $ip );
	}

	/**
	 * Log login attempt to database
	 *
	 * @param string $ip IP address.
	 * @param string $username Username.
	 * @param bool   $success Whether login was successful.
	 */
	private static function log_attempt( $ip, $username, $success ) {
		global $wpdb;
		
		// Get country code from IP
		$country_code = self::get_country_from_ip( $ip );
		
		$wpdb->insert(
			$wpdb->prefix . 'bearmor_login_attempts',
			array(
				'ip_address'   => $ip,
				'username'     => sanitize_user( $username ),
				'success'      => $success ? 1 : 0,
				'attempted_at' => current_time( 'mysql' ),
				'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 255 ) : '',
				'country_code' => $country_code,
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s' )
		);
	}

	/**
	 * Get country code from IP address using ip-api.com
	 *
	 * @param string $ip IP address.
	 * @return string Country code (e.g., 'US', 'EE', 'KP') or empty string.
	 */
	private static function get_country_from_ip( $ip ) {
		// Don't lookup local/private IPs
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false ) {
			return '';
		}
		
		// Check cache first (transient valid for 24 hours)
		$cache_key = 'bearmor_country_' . md5( $ip );
		$cached = get_transient( $cache_key );
		if ( $cached !== false ) {
			return $cached;
		}
		
		// Call ip-api.com
		$response = wp_remote_get( 
			'http://ip-api.com/json/' . $ip . '?fields=countryCode',
			array( 'timeout' => 2 )
		);
		
		if ( is_wp_error( $response ) ) {
			return '';
		}
		
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body );
		
		if ( isset( $data->countryCode ) ) {
			$country_code = strtoupper( $data->countryCode );
			// Cache for 24 hours
			set_transient( $cache_key, $country_code, DAY_IN_SECONDS );
			return $country_code;
		}
		
		return '';
	}

	/**
	 * Get failed attempts count for IP in last hour
	 *
	 * @param string $ip IP address.
	 * @return int Failed attempts count.
	 */
	private static function get_failed_attempts_count( $ip ) {
		global $wpdb;
		
		// Count ALL failed attempts in last hour
		$one_hour_ago = date( 'Y-m-d H:i:s', strtotime( '-1 hour' ) );
		
		return (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_attempts 
			WHERE ip_address = %s 
			AND success = 0 
			AND attempted_at > %s",
			$ip,
			$one_hour_ago
		) );
	}

	/**
	 * Clear failed attempts for IP
	 *
	 * @param string $ip IP address.
	 */
	private static function clear_failed_attempts( $ip ) {
		global $wpdb;
		
		$wpdb->delete(
			$wpdb->prefix . 'bearmor_login_attempts',
			array(
				'ip_address' => $ip,
				'success'    => 0,
			),
			array( '%s', '%d' )
		);
	}

	/**
	 * Block an IP address
	 *
	 * @param string $ip IP address.
	 * @param string $duration Duration (e.g., '5 minutes', '24 hours').
	 * @param string $reason Reason for blocking.
	 * @param bool   $permanent Whether block is permanent.
	 */
	public static function block_ip( $ip, $duration = null, $reason = '', $permanent = false ) {
		global $wpdb;
		
		$expires_at = null;
		if ( ! $permanent && $duration ) {
			$expires_at = date( 'Y-m-d H:i:s', strtotime( '+' . $duration ) );
		}
		
		// Check if already blocked
		$existing = self::get_ip_block( $ip );
		
		if ( $existing ) {
			// Update existing block
			$wpdb->update(
				$wpdb->prefix . 'bearmor_blocked_ips',
				array(
					'expires_at' => $expires_at,
					'reason'     => $reason,
					'permanent'  => $permanent ? 1 : 0,
					'blocked_at' => current_time( 'mysql' ),
				),
				array( 'ip_address' => $ip ),
				array( '%s', '%s', '%d', '%s' ),
				array( '%s' )
			);
		} else {
			// Insert new block
			$wpdb->insert(
				$wpdb->prefix . 'bearmor_blocked_ips',
				array(
					'ip_address' => $ip,
					'blocked_at' => current_time( 'mysql' ),
					'expires_at' => $expires_at,
					'reason'     => $reason,
					'permanent'  => $permanent ? 1 : 0,
					'blocked_by' => get_current_user_id(),
				),
				array( '%s', '%s', '%s', '%s', '%d', '%d' )
			);
		}
	}

	/**
	 * Unblock an IP address
	 *
	 * @param string $ip IP address.
	 */
	public static function unblock_ip( $ip ) {
		global $wpdb;
		
		$wpdb->delete(
			$wpdb->prefix . 'bearmor_blocked_ips',
			array( 'ip_address' => $ip ),
			array( '%s' )
		);
		
		// Clear failed attempts when manually unblocking
		self::clear_failed_attempts( $ip );
	}

	/**
	 * Get IP block record
	 *
	 * @param string $ip IP address.
	 * @return object|null Block record or null.
	 */
	private static function get_ip_block( $ip ) {
		global $wpdb;
		
		return $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}bearmor_blocked_ips WHERE ip_address = %s",
			$ip
		) );
	}

	/**
	 * Check if IP is whitelisted
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private static function is_ip_whitelisted( $ip ) {
		$whitelist = get_option( 'bearmor_ip_whitelist', array() );
		return in_array( $ip, $whitelist, true );
	}

	/**
	 * Add IP to whitelist
	 *
	 * @param string $ip IP address.
	 */
	public static function whitelist_ip( $ip ) {
		$whitelist = get_option( 'bearmor_ip_whitelist', array() );
		if ( ! in_array( $ip, $whitelist, true ) ) {
			$whitelist[] = $ip;
			update_option( 'bearmor_ip_whitelist', $whitelist );
		}
		
		// Remove from blocked list if present
		self::unblock_ip( $ip );
	}

	/**
	 * Remove IP from whitelist
	 *
	 * @param string $ip IP address.
	 */
	public static function remove_from_whitelist( $ip ) {
		$whitelist = get_option( 'bearmor_ip_whitelist', array() );
		$whitelist = array_diff( $whitelist, array( $ip ) );
		update_option( 'bearmor_ip_whitelist', array_values( $whitelist ) );
	}

	/**
	 * Get client IP address
	 *
	 * @return string IP address.
	 */
	private static function get_client_ip() {
		$ip = '';
		
		if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			// Cloudflare
			$ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
		} elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			// Proxy
			$ip = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] )[0];
		} elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		
		return filter_var( trim( $ip ), FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}

	/**
	 * Clean up expired blocks and old login attempts
	 */
	public static function cleanup_expired_blocks() {
		global $wpdb;
		
		// Remove expired blocks
		$wpdb->query(
			"DELETE FROM {$wpdb->prefix}bearmor_blocked_ips 
			WHERE permanent = 0 
			AND expires_at IS NOT NULL 
			AND expires_at < NOW()"
		);
		
		// Keep only last 1000 login attempts
		$wpdb->query(
			"DELETE FROM {$wpdb->prefix}bearmor_login_attempts 
			WHERE id NOT IN (
				SELECT id FROM (
					SELECT id FROM {$wpdb->prefix}bearmor_login_attempts 
					ORDER BY attempted_at DESC 
					LIMIT 1000
				) AS keep_ids
			)"
		);
	}

	/**
	 * Get all login attempts
	 *
	 * @param array $args Query arguments.
	 * @return array Login attempts.
	 */
	public static function get_login_attempts( $args = array() ) {
		global $wpdb;
		
		$defaults = array(
			'success' => null,
			'limit'   => 100,
			'offset'  => 0,
		);
		
		$args = wp_parse_args( $args, $defaults );
		
		$where = '1=1';
		if ( $args['success'] !== null ) {
			$where .= $wpdb->prepare( ' AND success = %d', $args['success'] );
		}
		
		return $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}bearmor_login_attempts 
			WHERE {$where} 
			ORDER BY attempted_at DESC 
			LIMIT {$args['limit']} OFFSET {$args['offset']}"
		);
	}

	/**
	 * Get all blocked IPs
	 *
	 * @return array Blocked IPs.
	 */
	public static function get_blocked_ips() {
		global $wpdb;
		
		return $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}bearmor_blocked_ips 
			ORDER BY blocked_at DESC"
		);
	}

	/**
	 * Send email notification for 24-hour lockout
	 *
	 * @param string $ip IP address.
	 * @param string $username Username attempted.
	 * @param int    $failed_count Number of failed attempts.
	 */
	private static function send_lockout_notification( $ip, $username, $failed_count ) {
		// Get country code
		global $wpdb;
		$country_code = $wpdb->get_var( $wpdb->prepare(
			"SELECT country_code FROM {$wpdb->prefix}bearmor_login_attempts 
			WHERE ip_address = %s 
			ORDER BY attempted_at DESC 
			LIMIT 1",
			$ip
		) );
		
		$country_flag = $country_code ? self::get_country_flag( $country_code ) : '';
		$country_name = $country_code ? self::get_country_name( $country_code ) : 'Unknown';
		
		// Email details
		$to = get_option( 'admin_email' );
		$subject = '🚨 Bearmor Security: IP Blocked for 24 Hours';
		
		$message = "Bearmor Security has blocked an IP address for 24 hours due to repeated failed login attempts.\n\n";
		$message .= "SECURITY ALERT DETAILS:\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
		$message .= "🌍 IP Address: {$ip}\n";
		$message .= "🚩 Country: {$country_flag} {$country_name} ({$country_code})\n";
		$message .= "👤 Username Attempted: {$username}\n";
		$message .= "🔢 Failed Attempts: {$failed_count} in the last hour\n";
		$message .= "⏰ Blocked At: " . current_time( 'Y-m-d H:i:s' ) . "\n";
		$message .= "🔒 Block Duration: 24 hours\n\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
		$message .= "WHAT THIS MEANS:\n";
		$message .= "• Someone (or a bot) tried to login {$failed_count} times with wrong credentials\n";
		$message .= "• The IP has been automatically blocked for 24 hours\n";
		$message .= "• No action needed unless you recognize this activity\n\n";
		$message .= "NEED TO UNBLOCK?\n";
		$message .= "Visit: " . admin_url( 'admin.php?page=bearmor-login-activity' ) . "\n\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
		$message .= "Protected by Bearmor Security Plugin\n";
		$message .= get_site_url() . "\n";
		
		$headers = array(
			'From: Bearmor Security <' . get_option( 'admin_email' ) . '>',
		);
		
		wp_mail( $to, $subject, $message, $headers );
	}

	/**
	 * Get country flag emoji from country code
	 *
	 * @param string $country_code Two-letter country code.
	 * @return string Flag emoji.
	 */
	private static function get_country_flag( $country_code ) {
		if ( empty( $country_code ) || strlen( $country_code ) !== 2 ) {
			return '🏳️';
		}
		
		// Convert country code to flag emoji
		$code = strtoupper( $country_code );
		$flag = '';
		for ( $i = 0; $i < 2; $i++ ) {
			$flag .= mb_chr( ord( $code[ $i ] ) + 127397, 'UTF-8' );
		}
		return $flag;
	}

	/**
	 * Get country name from country code
	 *
	 * @param string $country_code Two-letter country code.
	 * @return string Country name.
	 */
	private static function get_country_name( $country_code ) {
		$countries = array(
			'EE' => 'Estonia',
			'US' => 'United States',
			'GB' => 'United Kingdom',
			'DE' => 'Germany',
			'FR' => 'France',
			'RU' => 'Russia',
			'CN' => 'China',
			'KP' => 'North Korea',
			'IN' => 'India',
			'BR' => 'Brazil',
			'CA' => 'Canada',
			'AU' => 'Australia',
			'JP' => 'Japan',
			'KR' => 'South Korea',
			'ES' => 'Spain',
			'IT' => 'Italy',
			'NL' => 'Netherlands',
			'SE' => 'Sweden',
			'NO' => 'Norway',
			'FI' => 'Finland',
			'PL' => 'Poland',
			'UA' => 'Ukraine',
		);
		
		return isset( $countries[ $country_code ] ) ? $countries[ $country_code ] : $country_code;
	}
}
