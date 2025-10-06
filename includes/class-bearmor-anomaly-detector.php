<?php
/**
 * Anomaly Detector Class
 *
 * Detects suspicious login patterns and assigns risk scores
 *
 * @package Bearmor_Security
 */

class Bearmor_Anomaly_Detector {

	/**
	 * Anomaly score thresholds
	 */
	const SCORE_IMPOSSIBLE_TRAVEL = 90;
	const SCORE_TOR_VPN = 70;
	const SCORE_NEW_COUNTRY = 50;
	const SCORE_NEW_DEVICE = 40;
	const SCORE_UNUSUAL_TIME = 30;

	/**
	 * Initialize hooks
	 */
	public static function init() {
		// Check for anomalies on successful login
		add_action( 'wp_login', array( __CLASS__, 'check_login_anomalies' ), 20, 2 );
	}

	/**
	 * Check for login anomalies
	 *
	 * @param string  $username Username.
	 * @param WP_User $user User object.
	 */
	public static function check_login_anomalies( $username, $user ) {
		$user_id = $user->ID;
		$ip = self::get_client_ip();
		$country = self::get_country_from_login_attempts( $ip );
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
		
		// Get or create user profile
		$profile = self::get_user_profile( $user_id );
		if ( ! $profile ) {
			// First login, create profile
			self::create_user_profile( $user_id, $ip, $country, $user_agent );
			return;
		}

		// Check for anomalies
		$anomalies = array();

		// 1. Impossible Travel
		$impossible_travel = self::detect_impossible_travel( $user_id, $ip, $country, $profile );
		if ( $impossible_travel ) {
			$anomalies[] = $impossible_travel;
		}

		// 2. New Country
		$new_country = self::detect_new_country( $country, $profile );
		if ( $new_country ) {
			$anomalies[] = $new_country;
		}

		// 3. New Device
		$new_device = self::detect_new_device( $user_agent, $profile );
		if ( $new_device ) {
			$anomalies[] = $new_device;
		}

		// 4. Unusual Time
		$unusual_time = self::detect_unusual_time( $profile );
		if ( $unusual_time ) {
			$anomalies[] = $unusual_time;
		}

		// Log anomalies if any detected
		if ( ! empty( $anomalies ) ) {
			foreach ( $anomalies as $anomaly ) {
				self::log_anomaly( $user_id, $ip, $country, $user_agent, $anomaly );
			}
		}

		// Update user profile
		self::update_user_profile( $user_id, $ip, $country, $user_agent );
	}

	/**
	 * Detect impossible travel (login from different countries too quickly)
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip Current IP.
	 * @param string $country Current country.
	 * @param object $profile User profile.
	 * @return array|null Anomaly data or null.
	 */
	private static function detect_impossible_travel( $user_id, $ip, $country, $profile ) {
		if ( empty( $country ) || empty( $profile->last_login_country ) ) {
			return null;
		}

		// Same country = no travel
		if ( $country === $profile->last_login_country ) {
			return null;
		}

		// Check time since last login
		$last_login_time = strtotime( $profile->last_login_at );
		$current_time = current_time( 'timestamp' );
		$time_diff_hours = ( $current_time - $last_login_time ) / 3600;

		// If less than 2 hours between logins from different countries = impossible
		if ( $time_diff_hours < 2 ) {
			return array(
				'type'    => 'impossible_travel',
				'score'   => self::SCORE_IMPOSSIBLE_TRAVEL,
				'details' => sprintf(
					'Login from %s only %.1f hours after login from %s',
					$country,
					$time_diff_hours,
					$profile->last_login_country
				),
			);
		}

		return null;
	}

	/**
	 * Detect new country
	 *
	 * @param string $country Current country.
	 * @param object $profile User profile.
	 * @return array|null Anomaly data or null.
	 */
	private static function detect_new_country( $country, $profile ) {
		if ( empty( $country ) ) {
			return null;
		}

		$known_countries = ! empty( $profile->known_countries ) ? json_decode( $profile->known_countries, true ) : array();
		
		if ( ! in_array( $country, $known_countries, true ) ) {
			return array(
				'type'    => 'new_country',
				'score'   => self::SCORE_NEW_COUNTRY,
				'details' => sprintf( 'First login from %s', $country ),
			);
		}

		return null;
	}

	/**
	 * Detect new device (user agent)
	 *
	 * @param string $user_agent Current user agent.
	 * @param object $profile User profile.
	 * @return array|null Anomaly data or null.
	 */
	private static function detect_new_device( $user_agent, $profile ) {
		if ( empty( $user_agent ) ) {
			return null;
		}

		// Simplify user agent to browser + OS
		$simplified_ua = self::simplify_user_agent( $user_agent );
		$known_agents = ! empty( $profile->known_user_agents ) ? json_decode( $profile->known_user_agents, true ) : array();
		
		if ( ! in_array( $simplified_ua, $known_agents, true ) ) {
			return array(
				'type'    => 'new_device',
				'score'   => self::SCORE_NEW_DEVICE,
				'details' => sprintf( 'First login from device: %s', $simplified_ua ),
			);
		}

		return null;
	}

	/**
	 * Detect unusual login time
	 *
	 * @param object $profile User profile.
	 * @return array|null Anomaly data or null.
	 */
	private static function detect_unusual_time( $profile ) {
		$current_hour = (int) current_time( 'H' );
		$typical_hours = ! empty( $profile->typical_login_hours ) ? json_decode( $profile->typical_login_hours, true ) : array();

		// Need at least 5 logins to establish pattern
		if ( count( $typical_hours ) < 5 ) {
			return null;
		}

		// Calculate average and standard deviation
		$avg = array_sum( $typical_hours ) / count( $typical_hours );
		$variance = 0;
		foreach ( $typical_hours as $hour ) {
			$variance += pow( $hour - $avg, 2 );
		}
		$std_dev = sqrt( $variance / count( $typical_hours ) );

		// If current hour is more than 2 standard deviations away = unusual
		if ( abs( $current_hour - $avg ) > ( 2 * $std_dev ) ) {
			return array(
				'type'    => 'unusual_time',
				'score'   => self::SCORE_UNUSUAL_TIME,
				'details' => sprintf(
					'Login at %d:00 (typical: %d:00 ± %.1f hours)',
					$current_hour,
					(int) $avg,
					$std_dev
				),
			);
		}

		return null;
	}

	/**
	 * Log anomaly to database
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip IP address.
	 * @param string $country Country code.
	 * @param string $user_agent User agent.
	 * @param array  $anomaly Anomaly data.
	 */
	private static function log_anomaly( $user_id, $ip, $country, $user_agent, $anomaly ) {
		global $wpdb;

		$wpdb->insert(
			$wpdb->prefix . 'bearmor_login_anomalies',
			array(
				'user_id'       => $user_id,
				'ip_address'    => $ip,
				'country_code'  => $country,
				'user_agent'    => $user_agent,
				'anomaly_type'  => $anomaly['type'],
				'anomaly_score' => $anomaly['score'],
				'details'       => $anomaly['details'],
				'detected_at'   => current_time( 'mysql' ),
				'status'        => 'new',
			),
			array( '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		// Send email notification for critical anomalies (score >= 80)
		if ( $anomaly['score'] >= 80 ) {
			self::send_anomaly_notification( $user_id, $ip, $country, $anomaly );
		}
	}

	/**
	 * Get user profile
	 *
	 * @param int $user_id User ID.
	 * @return object|null Profile or null.
	 */
	private static function get_user_profile( $user_id ) {
		global $wpdb;

		return $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}bearmor_user_profiles WHERE user_id = %d",
			$user_id
		) );
	}

	/**
	 * Create user profile
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip IP address.
	 * @param string $country Country code.
	 * @param string $user_agent User agent.
	 */
	private static function create_user_profile( $user_id, $ip, $country, $user_agent ) {
		global $wpdb;

		$current_hour = (int) current_time( 'H' );
		$simplified_ua = self::simplify_user_agent( $user_agent );

		$wpdb->insert(
			$wpdb->prefix . 'bearmor_user_profiles',
			array(
				'user_id'              => $user_id,
				'known_ips'            => json_encode( array( $ip ) ),
				'known_countries'      => json_encode( $country ? array( $country ) : array() ),
				'known_user_agents'    => json_encode( array( $simplified_ua ) ),
				'typical_login_hours'  => json_encode( array( $current_hour ) ),
				'last_login_at'        => current_time( 'mysql' ),
				'last_login_ip'        => $ip,
				'last_login_country'   => $country,
				'profile_created'      => current_time( 'mysql' ),
				'profile_updated'      => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Update user profile
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip IP address.
	 * @param string $country Country code.
	 * @param string $user_agent User agent.
	 */
	private static function update_user_profile( $user_id, $ip, $country, $user_agent ) {
		global $wpdb;

		$profile = self::get_user_profile( $user_id );
		if ( ! $profile ) {
			return;
		}

		// Update known IPs (keep last 10)
		$known_ips = json_decode( $profile->known_ips, true );
		if ( ! in_array( $ip, $known_ips, true ) ) {
			$known_ips[] = $ip;
			$known_ips = array_slice( $known_ips, -10 );
		}

		// Update known countries (keep last 5)
		$known_countries = json_decode( $profile->known_countries, true );
		if ( $country && ! in_array( $country, $known_countries, true ) ) {
			$known_countries[] = $country;
			$known_countries = array_slice( $known_countries, -5 );
		}

		// Update known user agents (keep last 5)
		$simplified_ua = self::simplify_user_agent( $user_agent );
		$known_agents = json_decode( $profile->known_user_agents, true );
		if ( ! in_array( $simplified_ua, $known_agents, true ) ) {
			$known_agents[] = $simplified_ua;
			$known_agents = array_slice( $known_agents, -5 );
		}

		// Update typical login hours (keep last 20)
		$current_hour = (int) current_time( 'H' );
		$typical_hours = json_decode( $profile->typical_login_hours, true );
		$typical_hours[] = $current_hour;
		$typical_hours = array_slice( $typical_hours, -20 );

		$wpdb->update(
			$wpdb->prefix . 'bearmor_user_profiles',
			array(
				'known_ips'            => json_encode( $known_ips ),
				'known_countries'      => json_encode( $known_countries ),
				'known_user_agents'    => json_encode( $known_agents ),
				'typical_login_hours'  => json_encode( $typical_hours ),
				'last_login_at'        => current_time( 'mysql' ),
				'last_login_ip'        => $ip,
				'last_login_country'   => $country,
				'profile_updated'      => current_time( 'mysql' ),
			),
			array( 'user_id' => $user_id ),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Simplify user agent to browser + OS
	 *
	 * @param string $user_agent Full user agent string.
	 * @return string Simplified user agent.
	 */
	private static function simplify_user_agent( $user_agent ) {
		// Extract browser (order matters! Check most specific first)
		$browser = 'Unknown';
		if ( strpos( $user_agent, 'OPR' ) !== false || strpos( $user_agent, 'Opera' ) !== false ) {
			$browser = 'Opera';
		} elseif ( strpos( $user_agent, 'Edg' ) !== false || strpos( $user_agent, 'Edge' ) !== false ) {
			$browser = 'Edge';
		} elseif ( strpos( $user_agent, 'Vivaldi' ) !== false ) {
			$browser = 'Vivaldi';
		} elseif ( strpos( $user_agent, 'Brave' ) !== false ) {
			$browser = 'Brave';
		} elseif ( strpos( $user_agent, 'Chrome' ) !== false ) {
			$browser = 'Chrome';
		} elseif ( strpos( $user_agent, 'Firefox' ) !== false ) {
			$browser = 'Firefox';
		} elseif ( strpos( $user_agent, 'Safari' ) !== false ) {
			$browser = 'Safari';
		}

		// Extract OS
		$os = 'Unknown';
		if ( strpos( $user_agent, 'Windows' ) !== false ) {
			$os = 'Windows';
		} elseif ( strpos( $user_agent, 'Mac' ) !== false ) {
			$os = 'Mac';
		} elseif ( strpos( $user_agent, 'Android' ) !== false ) {
			$os = 'Android';
		} elseif ( strpos( $user_agent, 'iPhone' ) !== false || strpos( $user_agent, 'iPad' ) !== false ) {
			$os = 'iOS';
		} elseif ( strpos( $user_agent, 'Linux' ) !== false ) {
			$os = 'Linux';
		}

		return $browser . ' on ' . $os;
	}

	/**
	 * Get country from recent login attempts
	 *
	 * @param string $ip IP address.
	 * @return string Country code or empty.
	 */
	private static function get_country_from_login_attempts( $ip ) {
		global $wpdb;

		return (string) $wpdb->get_var( $wpdb->prepare(
			"SELECT country_code FROM {$wpdb->prefix}bearmor_login_attempts 
			WHERE ip_address = %s 
			ORDER BY attempted_at DESC 
			LIMIT 1",
			$ip
		) );
	}

	/**
	 * Get client IP address
	 *
	 * @return string IP address.
	 */
	private static function get_client_ip() {
		$ip = '';
		
		if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
		} elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] )[0];
		} elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		
		return filter_var( trim( $ip ), FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}

	/**
	 * Send email notification for critical anomaly
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip IP address.
	 * @param string $country Country code.
	 * @param array  $anomaly Anomaly data.
	 */
	private static function send_anomaly_notification( $user_id, $ip, $country, $anomaly ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$to = get_option( 'admin_email' );
		$subject = '🚨 Bearmor Security: Critical Login Anomaly Detected';
		
		$message = "Bearmor Security has detected a critical login anomaly.\n\n";
		$message .= "SECURITY ALERT DETAILS:\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
		$message .= "👤 User: {$user->user_login} ({$user->user_email})\n";
		$message .= "🌍 IP Address: {$ip}\n";
		$message .= "🚩 Country: {$country}\n";
		$message .= "🚨 Anomaly Type: " . ucwords( str_replace( '_', ' ', $anomaly['type'] ) ) . "\n";
		$message .= "📊 Risk Score: {$anomaly['score']}/100\n";
		$message .= "📝 Details: {$anomaly['details']}\n";
		$message .= "⏰ Detected At: " . current_time( 'Y-m-d H:i:s' ) . "\n\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
		$message .= "RECOMMENDED ACTIONS:\n";
		$message .= "• Review the login anomaly details\n";
		$message .= "• Contact the user if suspicious\n";
		$message .= "• Block IP if confirmed attack\n";
		$message .= "• Force password reset if compromised\n\n";
		$message .= "VIEW DETAILS:\n";
		$message .= admin_url( 'admin.php?page=bearmor-login-anomalies' ) . "\n\n";
		$message .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
		$message .= "Protected by Bearmor Security Plugin\n";
		$message .= get_site_url() . "\n";
		
		$headers = array(
			'From: Bearmor Security <' . get_option( 'admin_email' ) . '>',
		);
		
		wp_mail( $to, $subject, $message, $headers );
	}

	/**
	 * Get all anomalies
	 *
	 * @param array $args Query arguments.
	 * @return array Anomalies.
	 */
	public static function get_anomalies( $args = array() ) {
		global $wpdb;
		
		$defaults = array(
			'status' => null,
			'limit'  => 100,
			'offset' => 0,
		);
		
		$args = wp_parse_args( $args, $defaults );
		
		$where = '1=1';
		if ( $args['status'] !== null ) {
			$where .= $wpdb->prepare( ' AND status = %s', $args['status'] );
		}
		
		return $wpdb->get_results(
			"SELECT a.*, u.user_login, u.user_email 
			FROM {$wpdb->prefix}bearmor_login_anomalies a
			LEFT JOIN {$wpdb->users} u ON a.user_id = u.ID
			WHERE {$where} 
			ORDER BY detected_at DESC 
			LIMIT {$args['limit']} OFFSET {$args['offset']}"
		);
	}

	/**
	 * Mark anomaly as safe
	 *
	 * @param int $anomaly_id Anomaly ID.
	 */
	public static function mark_safe( $anomaly_id ) {
		global $wpdb;
		
		$wpdb->update(
			$wpdb->prefix . 'bearmor_login_anomalies',
			array(
				'status'    => 'marked_safe',
				'action_by' => get_current_user_id(),
			),
			array( 'id' => $anomaly_id ),
			array( '%s', '%d' ),
			array( '%d' )
		);
	}

	/**
	 * Block IP from anomaly
	 *
	 * @param int $anomaly_id Anomaly ID.
	 */
	public static function block_from_anomaly( $anomaly_id ) {
		global $wpdb;
		
		$anomaly = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}bearmor_login_anomalies WHERE id = %d",
			$anomaly_id
		) );
		
		if ( ! $anomaly ) {
			return;
		}
		
		// Block the IP permanently
		Bearmor_Login_Protection::block_ip( $anomaly->ip_address, null, 'Blocked from anomaly detection', true );
		
		// Update anomaly status
		$wpdb->update(
			$wpdb->prefix . 'bearmor_login_anomalies',
			array(
				'status'    => 'blocked',
				'action_by' => get_current_user_id(),
			),
			array( 'id' => $anomaly_id ),
			array( '%s', '%d' ),
			array( '%d' )
		);
	}
}
