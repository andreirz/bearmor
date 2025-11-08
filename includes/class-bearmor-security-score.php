<?php
/**
 * Security Score Calculator
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Security_Score {

	/**
	 * Calculate FREE user security score (max 70)
	 *
	 * @return array Score data: score, grade, color, breakdown
	 */
	public static function calculate_free_score() {
		$score = 0;
		$breakdown = array();

		// 1. No malware detected: +45
		$threats = Bearmor_Malware_Scanner::get_threats( 'pending' );
		if ( empty( $threats ) ) {
			$score += 45;
			$breakdown['malware'] = array(
				'label' => 'No malware detected',
				'points' => 45,
				'status' => 'good',
			);
		} else {
			$breakdown['malware'] = array(
				'label' => 'Threats detected: ' . count( $threats ),
				'points' => 0,
				'status' => 'critical',
			);
		}

		// 2. Any hardening applied: +15
		$hardening_options = array(
			'bearmor_header_x_frame',
			'bearmor_header_content_type',
			'bearmor_header_referrer',
			'bearmor_header_permissions',
			'bearmor_header_xss',
			'bearmor_hide_wp_version',
			'bearmor_block_user_enum',
			'bearmor_disable_login_errors',
			'bearmor_disable_xmlrpc',
			'bearmor_force_ssl',
		);
		
		$hardening_applied = false;
		$hardening_count = 0;
		foreach ( $hardening_options as $option ) {
			if ( get_option( $option ) ) {
				$hardening_applied = true;
				$hardening_count++;
			}
		}
		
		if ( $hardening_applied ) {
			$score += 15;
			$breakdown['hardening'] = array(
				'label' => 'Hardening applied (' . $hardening_count . ' rules)',
				'points' => 15,
				'status' => 'good',
			);
		} else {
			$breakdown['hardening'] = array(
				'label' => 'No hardening applied',
				'points' => 0,
				'status' => 'warning',
			);
		}

		// 3. 2FA enabled: +5
		$two_fa_enabled = get_option( 'bearmor_2fa_enabled' );
		if ( $two_fa_enabled ) {
			$score += 5;
			$breakdown['2fa'] = array(
				'label' => '2FA enabled',
				'points' => 5,
				'status' => 'good',
			);
		} else {
			$breakdown['2fa'] = array(
				'label' => '2FA not enabled',
				'points' => 0,
				'status' => 'warning',
			);
		}

		// 4. SSL certificate: +5
		if ( is_ssl() ) {
			$score += 5;
			$breakdown['ssl'] = array(
				'label' => 'SSL certificate active',
				'points' => 5,
				'status' => 'good',
			);
		} else {
			$breakdown['ssl'] = array(
				'label' => 'No SSL certificate',
				'points' => 0,
				'status' => 'warning',
			);
		}

		// Cap at 70
		$score = min( $score, 70 );

		// Get grade and color
		$grade_data = self::get_grade_and_color( $score );

		return array(
			'score'       => $score,
			'grade'       => $grade_data['grade'],
			'color'       => $grade_data['color'],
			'label'       => $grade_data['label'],
			'breakdown'   => $breakdown,
		);
	}

	/**
	 * Get grade (A-F) and color based on score
	 *
	 * @param int $score Score 0-70
	 * @return array Grade, color, label
	 */
	public static function get_grade_and_color( $score ) {
		if ( $score >= 65 ) {
			return array(
				'grade' => 'A',
				'color' => 'green',
				'label' => 'Excellent',
			);
		} elseif ( $score >= 55 ) {
			return array(
				'grade' => 'B',
				'color' => 'green',
				'label' => 'Good',
			);
		} elseif ( $score >= 45 ) {
			return array(
				'grade' => 'C',
				'color' => 'yellow',
				'label' => 'Fair',
			);
		} elseif ( $score >= 35 ) {
			return array(
				'grade' => 'D',
				'color' => 'orange',
				'label' => 'Needs Attention',
			);
		} else {
			return array(
				'grade' => 'F',
				'color' => 'red',
				'label' => 'Critical',
			);
		}
	}

	/**
	 * Calculate PRO AI-powered security score (0-100, capped display)
	 *
	 * @return array Score data: score, grade, color, reasoning
	 */
	public static function calculate_pro_score() {
		// Check if API key is configured
		if ( ! defined( 'BEARMOR_OPENAI_KEY' ) || empty( BEARMOR_OPENAI_KEY ) ) {
			return array(
				'score'     => 0,
				'grade'     => 'F',
				'color'     => 'red',
				'label'     => 'Critical',
				'reasoning' => 'API not configured',
			);
		}

		// Build comprehensive security data
		$security_data = self::build_pro_security_data();

		// Call AI with scoring prompt
		$result = self::call_ai_for_score( $security_data );

		if ( is_wp_error( $result ) ) {
			error_log( 'BEARMOR PRO SCORE: AI error - ' . $result->get_error_message() );
			return array(
				'score'     => 0,
				'grade'     => 'F',
				'color'     => 'red',
				'label'     => 'Critical',
				'reasoning' => 'Score calculation failed',
			);
		}

		// Parse score from AI response
		$score = $result['score'];
		$reasoning = $result['reasoning'];

		// Cap display at 100
		$display_score = min( $score, 100 );

		// Get grade and color
		$grade_data = self::get_grade_and_color( $display_score );

		return array(
			'score'       => $display_score,
			'grade'       => $grade_data['grade'],
			'color'       => $grade_data['color'],
			'label'       => $grade_data['label'],
			'reasoning'   => $reasoning,
			'raw_score'   => $score, // Store raw score for debugging
		);
	}

	/**
	 * Build comprehensive security data for AI
	 *
	 * @return string Formatted security data
	 */
	private static function build_pro_security_data() {
		$data = "WORDPRESS SECURITY ASSESSMENT\n";
		$data .= "==============================\n\n";

		// Malware status
		$threats = Bearmor_Malware_Scanner::get_threats( 'pending' );
		$data .= "MALWARE STATUS:\n";
		$data .= "- Threats detected: " . count( $threats ) . "\n";
		if ( ! empty( $threats ) ) {
			$critical = count( array_filter( $threats, function( $t ) { return $t->severity === 'critical'; } ) );
			$high = count( array_filter( $threats, function( $t ) { return $t->severity === 'high'; } ) );
			$data .= "  - Critical: $critical, High: $high\n";
		}
		$data .= "\n";

		// Hardening status
		$hardening_options = array(
			'bearmor_header_x_frame' => 'X-Frame-Options header',
			'bearmor_header_content_type' => 'X-Content-Type-Options header',
			'bearmor_header_referrer' => 'Referrer-Policy header',
			'bearmor_header_permissions' => 'Permissions-Policy header',
			'bearmor_header_xss' => 'X-XSS-Protection header',
			'bearmor_hide_wp_version' => 'Hide WP version',
			'bearmor_block_user_enum' => 'Block user enumeration',
			'bearmor_disable_login_errors' => 'Disable verbose login errors',
			'bearmor_disable_xmlrpc' => 'Disable XML-RPC',
			'bearmor_force_ssl' => 'Force SSL',
		);
		
		$hardening_count = 0;
		$data .= "HARDENING RULES:\n";
		foreach ( $hardening_options as $option => $label ) {
			if ( get_option( $option ) ) {
				$data .= "- ✓ $label\n";
				$hardening_count++;
			}
		}
		$data .= "- Total enabled: $hardening_count/10\n\n";

		// 2FA status
		$data .= "2FA STATUS: " . ( get_option( 'bearmor_2fa_enabled' ) ? 'Enabled' : 'Disabled' ) . "\n\n";

		// SSL status
		$data .= "SSL CERTIFICATE: " . ( is_ssl() ? 'Active' : 'Not active' ) . "\n\n";

		// Firewall status (Pro feature)
		$data .= "FIREWALL: " . ( Bearmor_License::is_pro() ? 'Active (Pro)' : 'Not available' ) . "\n\n";

		// Recent activity
		$data .= "RECENT ACTIVITY (7 days):\n";
		$login_events = get_option( 'bearmor_login_events', array() );
		$blocked_logins = count( array_filter( $login_events, function( $e ) { return isset( $e['status'] ) && $e['status'] === 'blocked'; } ) );
		$data .= "- Login attempts: " . count( $login_events ) . "\n";
		$data .= "- Blocked logins: $blocked_logins\n";
		
		$anomalies = get_option( 'bearmor_login_anomalies', array() );
		$data .= "- Login anomalies: " . count( $anomalies ) . "\n\n";

		return $data;
	}

	/**
	 * Call AI for security score
	 *
	 * @param string $security_data Security data
	 * @return array|WP_Error Score and reasoning
	 */
	private static function call_ai_for_score( $security_data ) {
		$api_key = BEARMOR_OPENAI_KEY;

		$prompt = "You are a WordPress security expert. Analyze this site and give a SECURITY SCORE (0-100).\n\n";
		$prompt .= "SCORING RULES (60 fixed points max):\n";
		$prompt .= "- No malware detected: +25\n";
		$prompt .= "- Hardening rules enabled: +10\n";
		$prompt .= "- 2FA enabled: +5\n";
		$prompt .= "- SSL active: +5\n";
		$prompt .= "- Firewall active: +10\n";
		$prompt .= "- Uptime >99%: +5\n\n";
		$prompt .= "DISCRETIONARY POINTS (0-60, AI decides):\n";
		$prompt .= "- Based on activity logs, anomalies, blocked attacks, patterns\n";
		$prompt .= "- Excellent behavior = higher score\n";
		$prompt .= "- Suspicious patterns = lower score\n\n";
		$prompt .= "SECURITY DATA:\n{$security_data}\n\n";
		$prompt .= "Respond with: [SCORE: XX] followed by max 100 words reasoning.\n";

		$body = array(
			'model'       => 'gpt-4o-mini',
			'messages'    => array(
				array(
					'role'    => 'system',
					'content' => 'You are a WordPress security expert. Give accurate security scores 0-100 based on actual threat level and protections. Start with [SCORE: XX].',
				),
				array(
					'role'    => 'user',
					'content' => $prompt,
				),
			),
			'max_tokens'  => 300,
			'temperature' => 0.3,
		);

		$response = wp_remote_post( 'https://api.openai.com/v1/chat/completions', array(
			'headers' => array(
				'Authorization' => 'Bearer ' . $api_key,
				'Content-Type'  => 'application/json',
			),
			'body'    => wp_json_encode( $body ),
			'timeout' => 30,
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );
		$data        = json_decode( $body, true );

		if ( $status_code !== 200 ) {
			$error_message = isset( $data['error']['message'] ) ? $data['error']['message'] : 'Unknown API error';
			return new WP_Error( 'api_error', $error_message );
		}

		if ( ! isset( $data['choices'][0]['message']['content'] ) ) {
			return new WP_Error( 'invalid_response', 'Invalid API response' );
		}

		$content = $data['choices'][0]['message']['content'];

		// Extract score: [SCORE: XX]
		$score = 0;
		if ( preg_match( '/\[SCORE:\s*(\d+)\s*\]/i', $content, $matches ) ) {
			$score = (int) $matches[1];
			// Remove score tag from reasoning
			$reasoning = preg_replace( '/\[SCORE:\s*\d+\s*\]/i', '', $content );
		} else {
			$reasoning = $content;
		}

		// Trim reasoning to ~100 words
		$words = explode( ' ', trim( $reasoning ) );
		if ( count( $words ) > 100 ) {
			$reasoning = implode( ' ', array_slice( $words, 0, 100 ) ) . '...';
		}

		return array(
			'score'     => $score,
			'reasoning' => trim( $reasoning ),
		);
	}

	/**
	 * Initialize
	 */
	public static function init() {
		// Placeholder for future hooks
	}
}
