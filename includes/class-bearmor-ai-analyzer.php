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
		
		// Check if API key is defined
		if ( ! defined( 'BEARMOR_OPENAI_KEY' ) || empty( BEARMOR_OPENAI_KEY ) ) {
			error_log( 'BEARMOR AI: No API key configured' );
			return new WP_Error( 'no_api_key', 'OpenAI API key not configured' );
		}

		error_log( 'BEARMOR AI: Building summary...' );
		
		// Build summary
		$summary = Bearmor_Summary_Builder::build_summary( $days );
		
		error_log( 'BEARMOR AI: Summary built, length: ' . strlen( $summary ) );

		// Call OpenAI API
		error_log( 'BEARMOR AI: Calling OpenAI API...' );
		$response = self::call_openai_api( $summary );

		if ( is_wp_error( $response ) ) {
			error_log( 'BEARMOR AI: API error: ' . $response->get_error_message() );
			return $response;
		}

		error_log( 'BEARMOR AI: API response received, color: ' . $response['color'] );

		// Save to database
		error_log( 'BEARMOR AI: Saving to database...' );
		self::save_analysis( $summary, $response );
		
		error_log( 'BEARMOR AI: Analysis complete!' );

		return $response;
	}

	/**
	 * Call OpenAI API
	 *
	 * @param string $summary Security summary
	 * @return array|WP_Error API response or error
	 */
	private static function call_openai_api( $summary ) {
		$api_key = BEARMOR_OPENAI_KEY;

		$prompt = "You are a friendly WordPress security advisor helping a shop owner understand their site's security.\n\n";
		$prompt .= "CRITICAL: Start your response with [COLOR-RATING: X] where X is GREEN, GRAY, YELLOW, or RED.\n\n";
		$prompt .= "COLOR RATING RULES:\n";
		$prompt .= "- GREEN: Everything is great! Your site is secure and the security plugin is working perfectly.\n";
		$prompt .= "- GRAY: All good. Minor routine activity detected, but nothing to worry about. The plugin has everything under control.\n";
		$prompt .= "- YELLOW: Some attention needed. There are vulnerabilities to update or malware to clean, but the plugin is helping protect you.\n";
		$prompt .= "- RED: Urgent action needed. Active malware infections or critical vulnerabilities detected. The plugin is protecting you, but you need to act now.\n\n";
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
		$prompt .= "- Start with [COLOR-RATING: X]\n";
		$prompt .= "- Be kind, helpful, and reassuring\n";
		$prompt .= "- NO emojis\n";
		$prompt .= "- Use simple language (non-technical)\n";
		$prompt .= "- Don't stress the client - explain what's being done to protect them\n";
		$prompt .= "- If action is needed, make it sound manageable\n\n";
		$prompt .= "Security Report:\n{$summary}";

		$body = array(
			'model'       => self::MODEL,
			'messages'    => array(
				array(
					'role'    => 'system',
					'content' => 'You are a friendly, helpful WordPress security advisor. Your job is to help shop owners understand their site security in simple, non-technical language. Be reassuring and positive. You MUST start every response with [COLOR-RATING: X] where X is GREEN, GRAY, YELLOW, or RED. Remember: firewall blocks, failed logins, and login anomalies are GOOD - they mean the plugin is protecting the site.',
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
		
		// Extract color rating from response (new format: [COLOR-RATING: X])
		$color = 'gray'; // Default if AI doesn't provide
		if ( preg_match( '/\[COLOR-RATING:\s*(green|gray|yellow|red)\s*\]/i', $content, $matches ) ) {
			$color = strtolower( $matches[1] );
			// Strip the color tag from the response
			$content = preg_replace( '/\[COLOR-RATING:\s*(green|gray|yellow|red)\s*\]\s*/i', '', $content );
		}

		return array(
			'response'    => trim( $content ), // STRIPPED OF COLOR TAG
			'color'       => $color,
			'tokens_used' => isset( $data['usage']['total_tokens'] ) ? $data['usage']['total_tokens'] : 0,
			'model'       => self::MODEL,
			'prompt'      => $prompt, // SAVE PROMPT FOR DISPLAY
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
		
		$result = $wpdb->insert(
			$wpdb->prefix . 'bearmor_ai_analyses',
			array(
				'summary_data' => $summary,
				'ai_prompt'    => $response['prompt'],
				'ai_response'  => $response['response'],
				'color_rating' => isset( $response['color'] ) ? $response['color'] : 'gray',
				'model_used'   => $response['model'],
				'tokens_used'  => $response['tokens_used'],
				'created_at'   => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
		);
		
		if ( $result === false ) {
			error_log( 'Bearmor AI Analysis Save Error: ' . $wpdb->last_error );
		} else {
			error_log( 'Bearmor AI Analysis Saved: ID ' . $wpdb->insert_id . ', Color: ' . $response['color'] );
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
