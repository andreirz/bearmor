<?php
/**
 * AI Analyzer - OpenAI Integration
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_AI_Analyzer {

	/**
	 * OpenAI API endpoint
	 */
	const API_ENDPOINT = 'https://api.openai.com/v1/chat/completions';

	/**
	 * Model to use
	 */
	const MODEL = 'gpt-4o-mini';

	/**
	 * Run AI analysis
	 *
	 * @param int $days Number of days to analyze
	 * @return array|WP_Error Analysis result or error
	 */
	public static function analyze( $days = 7 ) {
		error_log( 'BEARMOR AI: analyze() called' );
		
		// Check if PRO
		$is_pro = class_exists( 'Bearmor_License' ) && Bearmor_License::is_pro();
		if ( ! $is_pro ) {
			error_log( 'BEARMOR AI: PRO license required' );
			return new WP_Error( 'pro_required', 'AI Analysis is a PRO feature' );
		}

		error_log( 'BEARMOR AI: Building summary...' );
		
		// Build summary
		$summary = Bearmor_Summary_Builder::build_summary( $days );
		
		error_log( 'BEARMOR AI: Summary built, length: ' . strlen( $summary ) );

		// Call bearmor-home API (proxies to OpenAI)
		error_log( 'BEARMOR AI: Calling bearmor-home AI endpoint...' );
		$response = self::call_home_ai_api( $summary );

		if ( is_wp_error( $response ) ) {
			error_log( 'BEARMOR AI: API error: ' . $response->get_error_message() );
			return $response;
		}

		error_log( 'BEARMOR AI: API response received' );

		// Save to database
		error_log( 'BEARMOR AI: Saving to database...' );
		self::save_analysis( $summary, $response );
		
		error_log( 'BEARMOR AI: Analysis complete!' );

		return $response;
	}

	/**
	 * Call bearmor-home AI API (proxies to OpenAI)
	 *
	 * @param string $summary Security summary
	 * @return array|WP_Error API response or error
	 */
	private static function call_home_ai_api( $summary ) {
		// Get site ID and home URL
		$site_id = get_option( 'bearmor_site_id' );
		$home_url = defined( 'BEARMOR_HOME_URL' ) ? BEARMOR_HOME_URL : 'https://bearmor.eu';
		
		if ( empty( $site_id ) ) {
			return new WP_Error( 'no_site_id', 'Site ID not found' );
		}

		// Build the full prompt with instructions
		$is_pro = class_exists( 'Bearmor_License' ) && Bearmor_License::is_pro();
		
		$system_message = "You are a WordPress security analyst. Analyze the data critically and provide accurate assessment. ALWAYS include [SCORE: XX] in your response.";
		
		$user_prompt = "SECURITY ANALYSIS INSTRUCTIONS:\n\n";
		$user_prompt .= "Do not blindly trust threat counts - analyze context:\n";
		$user_prompt .= "- base64_decode in JWT/OAuth/API plugins = legitimate\n";
		$user_prompt .= "- \"Silence is golden\" PHP files = WordPress placeholders (safe)\n";
		$user_prompt .= "- Failed login attempts = firewall working (good)\n";
		$user_prompt .= "- Firewall blocks = protection active (good)\n";
		$user_prompt .= "- File changes in plugins/themes = normal updates\n";
		$user_prompt .= "- Core file changes or unusual uploads = critical\n\n";
		$user_prompt .= "SCORING (max 50 points from AI):\n";
		$user_prompt .= "- 0 HIGH threats + working firewall = 45-50 points\n";
		$user_prompt .= "- 1-5 HIGH threats = 30-40 points\n";
		$user_prompt .= "- 10+ HIGH threats = 10-20 points\n";
		$user_prompt .= "- 50+ HIGH threats = 0-10 points\n";
		$user_prompt .= "- MEDIUM threats are informational, don't heavily penalize\n";
		$user_prompt .= "- Deduct for: core file changes, PHP in uploads, critical vulnerabilities\n";
		$user_prompt .= "- Bonus for: active firewall, recent updates, no anomalies\n\n";
		$user_prompt .= "Provide brief assessment (max 150 words). Include [SCORE: XX].\n\n";
		$user_prompt .= $summary;

		// Call bearmor-home AI endpoint
		$response = wp_remote_post( $home_url . '/wp-json/bearmor-home/v1/ai-analyze', array(
			'headers' => array(
				'Content-Type' => 'application/json',
			),
			'body'    => wp_json_encode( array(
				'site_id'        => $site_id,
				'system_message' => $system_message,
				'user_prompt'    => $user_prompt,
			) ),
			'timeout' => 30,
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );
		$data        = json_decode( $body, true );

		if ( $status_code === 403 && isset( $data['pro_required'] ) ) {
			return new WP_Error( 'pro_required', $data['message'] );
		}

		if ( $status_code !== 200 ) {
			$error_message = isset( $data['message'] ) ? $data['message'] : 'Unknown API error';
			error_log( 'BEARMOR AI: API error - Status: ' . $status_code . ', Response: ' . $body );
			return new WP_Error( 'api_error', $error_message . ' (Status: ' . $status_code . ')', array( 'status' => $status_code ) );
		}

		if ( ! isset( $data['ai_response'] ) ) {
			return new WP_Error( 'invalid_response', 'Invalid API response format' );
		}

		$content = $data['ai_response'];
		
		// Extract discretionary score and reason
		$discretionary_score = 0;
		$reason = '';
		
		// Try to match [SCORE: XX | REASON: explanation] format
		if ( preg_match( '/\[SCORE:\s*(\d+)\s*\|\s*REASON:\s*([^\]]+)\]/i', $content, $matches ) ) {
			$discretionary_score = (int) $matches[1];
			$reason = trim( $matches[2] );
			// Cap at 50
			$discretionary_score = min( $discretionary_score, 50 );
		} elseif ( preg_match( '/\[SCORE:\s*(\d+)\s*\]/i', $content, $matches ) ) {
			// Fallback: just [SCORE: XX]
			$discretionary_score = (int) $matches[1];
			$discretionary_score = min( $discretionary_score, 50 );
		}

		return array(
			'response'            => trim( $content ),
			'discretionary_score' => $discretionary_score,
			'score_reason'        => $reason,
			'tokens_used'         => isset( $data['tokens_used'] ) ? $data['tokens_used'] : 0,
			'model'               => isset( $data['model_used'] ) ? $data['model_used'] : 'gpt-4o-mini',
			'prompt'              => $summary, // Store summary as prompt
			'color'               => isset( $data['color_rating'] ) ? $data['color_rating'] : 'gray',
		);
	}

	/**
	 * OLD METHOD - DEPRECATED - Call OpenAI API directly
	 * Kept for reference, not used anymore
	 *
	 * @param string $summary Security summary
	 * @return array|WP_Error API response or error
	 */
	private static function call_openai_api_OLD( $summary ) {
		$api_key = BEARMOR_OPENAI_KEY;
		$is_pro = class_exists( 'Bearmor_License' ) && Bearmor_License::is_pro();

		// Build security settings data
		$security_settings = "SECURITY SETTINGS:\n";
		$security_settings .= "- Hardening rules enabled: " . ( get_option( 'bearmor_header_x_frame' ) ? 'Yes' : 'No' ) . " (Security headers, version hiding, user enumeration blocking)\n";
		$security_settings .= "- 2FA enabled: " . ( get_option( 'bearmor_2fa_enabled' ) ? 'Yes' : 'No' ) . " (Two-factor authentication for login protection)\n";
		$security_settings .= "- SSL active: " . ( is_ssl() ? 'Yes' : 'No' ) . " (HTTPS encryption for data in transit)\n";
		$security_settings .= "- Firewall active: " . ( $is_pro ? 'Yes (Pro)' : 'No (Free)' ) . " (Blocks incoming attacks: SQL injection, XSS, brute force, malicious requests - does NOT remove existing malware files)\n";
		$security_settings .= "\n";

		$prompt = "You are a friendly WordPress security advisor helping a shop owner understand their site's security.\n\n";
		
		// Ask for score for all users
		if ( $is_pro ) {
			$prompt .= "Based on the activity logs and patterns below, give 0-50 discretionary points.\n";
			$prompt .= "Respond with: [SCORE: XX | REASON: brief explanation] where XX is the discretionary score (0-50).\n\n";
		} else {
			$prompt .= "Respond with: [SCORE: XX | REASON: brief explanation] where XX is your assessment of security quality (0-50).\n\n";
		}

		$prompt .= "IMPORTANT - THESE ARE GOOD SIGNS:\n";
		$prompt .= "- Firewall blocks = Your plugin is protecting you from attacks\n";
		$prompt .= "- Failed login attempts = Your plugin is blocking hackers trying to break in\n";
		$prompt .= "- Login anomalies detected = Your plugin is watching for suspicious activity\n";
		$prompt .= "- File changes = Usually just WordPress or plugin updates (normal)\n\n";
		$prompt .= "Write a FRIENDLY, SHORT analysis (max 150 words):\n";
		$prompt .= "1. Start with overall status (reassuring tone)\n";
		$prompt .= "2. Explain what the plugin is protecting them from\n";
		$prompt .= "3. If real threats exist: explain calmly what to do\n";
		$prompt .= "4. Action steps (if any) - make them simple and clear\n\n";
		$prompt .= "TONE & RULES:\n";
		$prompt .= "- Be kind, helpful, and reassuring\n";
		$prompt .= "- NO emojis\n";
		$prompt .= "- Use simple language (non-technical)\n";
		$prompt .= "- Don't stress the client - explain what's being done to protect them\n";
		$prompt .= "- If action is needed, make it sound manageable\n";
		$prompt .= "- ALWAYS include [SCORE: XX] in your response\n";
		$prompt .= "\n";
		$prompt .= $security_settings;
		$prompt .= "Security Report:\n{$summary}";

		$body = array(
			'model'       => self::MODEL,
			'messages'    => array(
				array(
					'role'    => 'system',
					'content' => 'You are a friendly, helpful WordPress security advisor. Your job is to help shop owners understand their site security in simple, non-technical language. Be reassuring and positive. Remember: firewall blocks, failed logins, and login anomalies are GOOD - they mean the plugin is protecting the site. ALWAYS include [SCORE: XX] in your response.',
				),
				array(
					'role'    => 'user',
					'content' => $prompt,
				),
			),
			'max_tokens'  => 500,
			'temperature' => 0.3,
		);

		$response = wp_remote_post( self::API_ENDPOINT, array(
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
			return new WP_Error( 'api_error', $error_message, array( 'status' => $status_code ) );
		}

		if ( ! isset( $data['choices'][0]['message']['content'] ) ) {
			return new WP_Error( 'invalid_response', 'Invalid API response format' );
		}

		$content = $data['choices'][0]['message']['content'];
		
		// Extract discretionary score and reason
		$discretionary_score = 0;
		$reason = '';
		
		// Try to match [SCORE: XX | REASON: explanation] format
		if ( preg_match( '/\[SCORE:\s*(\d+)\s*\|\s*REASON:\s*([^\]]+)\]/i', $content, $matches ) ) {
			$discretionary_score = (int) $matches[1];
			$reason = trim( $matches[2] );
			// Cap at 50
			$discretionary_score = min( $discretionary_score, 50 );
		} elseif ( preg_match( '/\[SCORE:\s*(\d+)\s*\]/i', $content, $matches ) ) {
			// Fallback: just [SCORE: XX]
			$discretionary_score = (int) $matches[1];
			$discretionary_score = min( $discretionary_score, 50 );
		}

		return array(
			'response'           => trim( $content ),
			'discretionary_score' => $discretionary_score,
			'score_reason'       => $reason,
			'tokens_used'        => isset( $data['usage']['total_tokens'] ) ? $data['usage']['total_tokens'] : 0,
			'model'              => self::MODEL,
			'prompt'             => $prompt,
		);
	}

	/**
	 * Save analysis to database
	 *
	 * @param string $summary Summary text
	 * @param array  $response API response
	 */
	private static function save_analysis( $summary, $response ) {
		global $wpdb;

		// Delete all old analyses - we only keep the latest one
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bearmor_ai_analyses" );
		
		// Build insert data - sanitize to remove invalid UTF-8 and null bytes
		$insert_data = array(
			'summary_data' => mb_convert_encoding( $summary, 'UTF-8', 'UTF-8' ),
			'ai_prompt'    => mb_convert_encoding( $response['prompt'], 'UTF-8', 'UTF-8' ),
			'ai_response'  => mb_convert_encoding( $response['response'], 'UTF-8', 'UTF-8' ),
			'model_used'   => $response['model'],
			'tokens_used'  => $response['tokens_used'],
			'created_at'   => current_time( 'mysql' ),
		);
		
		$insert_formats = array( '%s', '%s', '%s', '%s', '%d', '%s' );
		
		// Add optional columns if they exist
		$table_name = $wpdb->prefix . 'bearmor_ai_analyses';
		$columns = $wpdb->get_results( "SHOW COLUMNS FROM {$table_name}" );
		$column_names = wp_list_pluck( $columns, 'Field' );
		
		error_log( 'BEARMOR AI: Table columns: ' . implode( ', ', $column_names ) );
		error_log( 'BEARMOR AI: Insert data keys: ' . implode( ', ', array_keys( $insert_data ) ) );
		error_log( 'BEARMOR AI: Insert formats: ' . implode( ', ', $insert_formats ) );
		
		if ( in_array( 'discretionary_score', $column_names ) ) {
			$insert_data['discretionary_score'] = isset( $response['discretionary_score'] ) ? $response['discretionary_score'] : 0;
			$insert_formats[] = '%d';
		}
		
		if ( in_array( 'score_reason', $column_names ) ) {
			$insert_data['score_reason'] = isset( $response['score_reason'] ) ? $response['score_reason'] : '';
			$insert_formats[] = '%s';
		}
		
		if ( in_array( 'color_rating', $column_names ) ) {
			$insert_data['color_rating'] = isset( $response['color'] ) ? $response['color'] : 'gray';
			$insert_formats[] = '%s';
		}
		
		// Log data sizes before insert
		error_log( 'BEARMOR AI: Data sizes - summary_data: ' . strlen( $insert_data['summary_data'] ) . ' bytes, ai_prompt: ' . strlen( $insert_data['ai_prompt'] ) . ' bytes' );
		
		// Enable MySQL error reporting
		$wpdb->show_errors();
		$wpdb->suppress_errors( false );
		
		$result = $wpdb->insert( $table_name, $insert_data, $insert_formats );
		
		if ( $result === false ) {
			// Get raw MySQL error
			global $EZSQL_ERROR;
			error_log( 'BEARMOR AI: Save failed!' );
			error_log( 'BEARMOR AI: wpdb->last_error: ' . $wpdb->last_error );
			error_log( 'BEARMOR AI: wpdb->last_query: ' . $wpdb->last_query );
			if ( ! empty( $EZSQL_ERROR ) ) {
				error_log( 'BEARMOR AI: Raw MySQL errors: ' . print_r( $EZSQL_ERROR, true ) );
			}
		} else {
			error_log( 'BEARMOR AI: Analysis saved successfully - ID: ' . $wpdb->insert_id );
		}
	}

	/**
	 * Get latest analysis
	 *
	 * @return array|null Latest analysis or null
	 */
	public static function get_latest_analysis() {
		global $wpdb;

		return $wpdb->get_row(
			"SELECT * FROM {$wpdb->prefix}bearmor_ai_analyses 
			ORDER BY created_at DESC LIMIT 1",
			ARRAY_A
		);
	}

	/**
	 * Check if analysis is fresh (less than 24 hours old)
	 *
	 * @return bool True if fresh analysis exists
	 */
	public static function has_fresh_analysis() {
		global $wpdb;

		$count = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_ai_analyses 
			WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
		);

		return $count > 0;
	}
}
