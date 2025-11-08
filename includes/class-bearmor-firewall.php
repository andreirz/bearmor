<?php
/**
 * Firewall Class
 * Web Application Firewall to block malicious requests
 *
 * @package Bearmor_Security
 */

class Bearmor_Firewall {

	/**
	 * Initialize firewall
	 */
	public static function init() {
		// Hook early to intercept requests
		add_action( 'init', array( __CLASS__, 'check_request' ), 1 );
	}

	/**
	 * Check incoming request for malicious patterns
	 */
	public static function check_request() {
		// Check if firewall is enabled
		$settings = get_option( 'bearmor_settings', array() );
		if ( isset( $settings['firewall_enabled'] ) && ! $settings['firewall_enabled'] ) {
			return; // Firewall disabled
		}

		// Skip checks for logged-in admins (performance optimization)
		if ( current_user_can( 'manage_options' ) ) {
			return;
		}

		// Skip checks for cron and AJAX
		if ( defined( 'DOING_CRON' ) || defined( 'DOING_AJAX' ) ) {
			return;
		}

		// Get request data
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$query_string = isset( $_SERVER['QUERY_STRING'] ) ? $_SERVER['QUERY_STRING'] : '';
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
		$ip_address = self::get_client_ip();

		// Rate limiting (Pro feature)
		if ( ! empty( $settings['firewall_rate_limiting'] ) ) {
			$rate_limit = isset( $settings['firewall_rate_limit'] ) ? intval( $settings['firewall_rate_limit'] ) : 100;
			if ( self::check_rate_limit( $ip_address, $rate_limit ) ) {
				self::block_request( 'Rate Limit Exceeded', $ip_address, $request_uri, $user_agent );
			}
		}

		// Country blocking (Pro feature)
		if ( ! empty( $settings['firewall_country_blocking'] ) && ! empty( $settings['firewall_blocked_countries'] ) ) {
			$country = self::get_country_code( $ip_address );
			$blocked_countries = explode( ',', $settings['firewall_blocked_countries'] );
			if ( $country && in_array( strtoupper( trim( $country ) ), array_map( 'trim', $blocked_countries ) ) ) {
				self::block_request( 'Country Blocked: ' . $country, $ip_address, $request_uri, $user_agent );
			}
		}

		// Check if IP is whitelisted
		if ( self::is_whitelisted_ip( $ip_address ) ) {
			return;
		}

		// Check if URI is whitelisted
		if ( self::is_whitelisted_uri( $request_uri ) ) {
			return;
		}

		// Combine all input for checking
		$input_data = array(
			'uri'          => $request_uri,
			'query_string' => $query_string,
			'get'          => $_GET,
			'post'         => $_POST,
			'cookies'      => $_COOKIE,
		);

		// Check for attacks
		$rule_matched = self::detect_attack( $input_data );

		if ( $rule_matched ) {
			self::block_request( $rule_matched, $ip_address, $request_uri, $user_agent );
		}
	}

	/**
	 * Detect attack patterns in request data
	 *
	 * @param array $input_data Request data to check
	 * @return string|false Matched rule name or false
	 */
	private static function detect_attack( $input_data ) {
		// SQL Injection patterns
		$sql_patterns = array(
			"'\\s*OR\\s*'1'\\s*=\\s*'1" => 'SQL Injection: OR 1=1',
			"'\\s*OR\\s*1\\s*=\\s*1"   => 'SQL Injection: OR 1=1',
			'\\bOR\\b.*=.*'            => 'SQL Injection: OR condition',
			'UNION.*SELECT'            => 'SQL Injection: UNION SELECT',
			'SELECT.*FROM'             => 'SQL Injection: SELECT FROM',
			'--\\s*$'                  => 'SQL Injection: Comment',
			';\\s*DROP\\s+TABLE'       => 'SQL Injection: DROP TABLE',
			';\\s*DELETE\\s+FROM'      => 'SQL Injection: DELETE FROM',
			'EXEC\\s*\\('              => 'SQL Injection: EXEC',
			'EXECUTE\\s*\\('           => 'SQL Injection: EXECUTE',
		);

		// XSS patterns
		$xss_patterns = array(
			'<script'                   => 'XSS: Script tag',
			'<\/script>'                => 'XSS: Script tag',
			'javascript:'               => 'XSS: JavaScript protocol',
			'onerror\\s*='              => 'XSS: onerror event',
			'onload\\s*='               => 'XSS: onload event',
			'onclick\\s*='              => 'XSS: onclick event',
			'<iframe'                   => 'XSS: iframe tag',
			'eval\\s*\\('               => 'XSS: eval function',
			'expression\\s*\\('         => 'XSS: CSS expression',
		);

		// Path Traversal patterns
		$traversal_patterns = array(
			'\\.\\.\/'           => 'Path Traversal: Directory traversal',
			'\\.\\.\\\\'         => 'Path Traversal: Directory traversal',
			'etc\/passwd'        => 'Path Traversal: /etc/passwd',
			'etc\/shadow'        => 'Path Traversal: /etc/shadow',
			'\\.\\.%2F'          => 'Path Traversal: Encoded traversal',
		);

		// Command Injection patterns
		$command_patterns = array(
			';\\s*rm\\s+-rf'     => 'Command Injection: rm -rf',
			'\\|\\s*cat\\s+'     => 'Command Injection: cat',
			'`.*`'               => 'Command Injection: Backticks',
			'\\$\\(.*\\)'        => 'Command Injection: Command substitution',
		);

		// Combine all patterns
		$all_patterns = array_merge( $sql_patterns, $xss_patterns, $traversal_patterns, $command_patterns );

		// Check each input field
		foreach ( $input_data as $key => $value ) {
			if ( is_array( $value ) ) {
				// Recursively check array values
				$result = self::check_array_recursive( $value, $all_patterns );
				if ( $result ) {
					return $result;
				}
			} else {
				// Check string value
				$result = self::check_string( $value, $all_patterns );
				if ( $result ) {
					return $result;
				}
			}
		}

		return false;
	}

	/**
	 * Recursively check array for malicious patterns
	 */
	private static function check_array_recursive( $array, $patterns ) {
		foreach ( $array as $value ) {
			if ( is_array( $value ) ) {
				$result = self::check_array_recursive( $value, $patterns );
				if ( $result ) {
					return $result;
				}
			} else {
				$result = self::check_string( $value, $patterns );
				if ( $result ) {
					return $result;
				}
			}
		}
		return false;
	}

	/**
	 * Check string against patterns
	 */
	private static function check_string( $string, $patterns ) {
		if ( ! is_string( $string ) ) {
			return false;
		}

		// Check both original and URL-decoded versions
		$strings_to_check = array(
			$string,
			urldecode( $string ),
		);

		foreach ( $strings_to_check as $check_string ) {
			foreach ( $patterns as $pattern => $rule_name ) {
				if ( preg_match( '/' . $pattern . '/i', $check_string ) ) {
					return $rule_name;
				}
			}
		}

		return false;
	}

	/**
	 * Block malicious request
	 */
	private static function block_request( $rule_matched, $ip_address, $request_uri, $user_agent ) {
		// Log the blocked request
		self::log_blocked_request( $ip_address, $request_uri, $rule_matched, $user_agent );

		// Send 403 Forbidden response
		status_header( 403 );
		nocache_headers();

		// Simple HTML response
		echo '<!DOCTYPE html>
<html>
<head>
	<title>403 Forbidden</title>
	<style>
		body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
		.container { max-width: 600px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		h1 { color: #d63638; margin: 0 0 20px; }
		p { color: #666; line-height: 1.6; }
		.code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
	</style>
</head>
<body>
	<div class="blocked-message">
		<h1>Access Forbidden</h1>
		<p>Your request was blocked by the security firewall.</p>
		<p>If you believe this is an error, please contact the site administrator.</p>
		<p><small>Incident ID: ' . esc_html( md5( $ip_address . time() ) ) . '</small></p>
	</div>
</body>
</html>';

		exit;
	}

	/**
	 * Log blocked request to database
	 */
	private static function log_blocked_request( $ip_address, $request_uri, $rule_matched, $user_agent ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_firewall_blocks';

		$wpdb->insert(
			$table_name,
			array(
				'ip_address'     => $ip_address,
				'request_uri'    => $request_uri,
				'request_method' => isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET',
				'user_agent'     => $user_agent,
				'rule_matched'   => $rule_matched,
				'blocked_at'     => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Get client IP address
	 */
	private static function get_client_ip() {
		$ip_keys = array(
			'HTTP_CF_CONNECTING_IP', // Cloudflare
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		);

		foreach ( $ip_keys as $key ) {
			if ( isset( $_SERVER[ $key ] ) && filter_var( $_SERVER[ $key ], FILTER_VALIDATE_IP ) ) {
				return $_SERVER[ $key ];
			}
		}

		return '0.0.0.0';
	}

	/**
	 * Check if IP is whitelisted
	 */
	private static function is_whitelisted_ip( $ip_address ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_firewall_whitelist';

		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $table_name WHERE whitelist_type = 'ip' AND value = %s",
				$ip_address
			)
		);

		return $count > 0;
	}

	/**
	 * Check if URI is whitelisted
	 */
	private static function is_whitelisted_uri( $request_uri ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_firewall_whitelist';

		$whitelisted_uris = $wpdb->get_col(
			"SELECT value FROM $table_name WHERE whitelist_type = 'uri'"
		);

		foreach ( $whitelisted_uris as $uri ) {
			if ( strpos( $request_uri, $uri ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Create database tables
	 */
	public static function create_tables() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();

		// Firewall blocks table
		$table_name = $wpdb->prefix . 'bearmor_firewall_blocks';
		$sql = "CREATE TABLE IF NOT EXISTS $table_name (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			ip_address VARCHAR(45) NOT NULL,
			request_uri TEXT NOT NULL,
			request_method VARCHAR(10),
			user_agent TEXT,
			rule_matched VARCHAR(255),
			blocked_at DATETIME NOT NULL,
			INDEX idx_ip_address (ip_address),
			INDEX idx_blocked_at (blocked_at)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		// Firewall whitelist table
		$table_name = $wpdb->prefix . 'bearmor_firewall_whitelist';
		$sql = "CREATE TABLE IF NOT EXISTS $table_name (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			whitelist_type ENUM('ip', 'uri') NOT NULL,
			value VARCHAR(500) NOT NULL,
			added_at DATETIME NOT NULL,
			INDEX idx_type (whitelist_type)
		) $charset_collate;";

		dbDelta( $sql );
	}

	/**
	 * Check rate limit for IP
	 *
	 * @param string $ip_address IP address
	 * @param int $limit Requests per minute
	 * @return bool True if rate limit exceeded
	 */
	private static function check_rate_limit( $ip_address, $limit ) {
		$transient_key = 'bearmor_rate_' . md5( $ip_address );
		$requests = get_transient( $transient_key );

		if ( false === $requests ) {
			// First request in this minute
			set_transient( $transient_key, 1, 60 ); // 60 seconds
			return false;
		}

		if ( $requests >= $limit ) {
			return true; // Rate limit exceeded
		}

		// Increment counter
		set_transient( $transient_key, $requests + 1, 60 );
		return false;
	}

	/**
	 * Get country code from IP address
	 *
	 * @param string $ip_address IP address
	 * @return string|false Country code or false
	 */
	private static function get_country_code( $ip_address ) {
		// Skip local/private IPs
		if ( filter_var( $ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false ) {
			return false;
		}

		// Check cache first
		$cache_key = 'bearmor_country_' . md5( $ip_address );
		$cached = get_transient( $cache_key );
		if ( $cached !== false ) {
			return $cached;
		}

		// Use ip-api.com (free, no key needed, 45 req/min limit)
		$response = wp_remote_get( "http://ip-api.com/json/{$ip_address}?fields=countryCode", array( 'timeout' => 2 ) );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( isset( $data['countryCode'] ) ) {
			$country_code = $data['countryCode'];
			// Cache for 24 hours
			set_transient( $cache_key, $country_code, DAY_IN_SECONDS );
			return $country_code;
		}

		return false;
	}
}
