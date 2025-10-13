<?php
/**
 * Database Scanner Class
 * Scans WordPress database for malicious code injections
 *
 * @package Bearmor_Security
 */

class Bearmor_DB_Scanner {

	/**
	 * Malicious patterns to detect
	 */
	private static $patterns = array(
		// Obfuscated code
		'eval\s*\(',
		'base64_decode\s*\(',
		'gzinflate\s*\(',
		'str_rot13\s*\(',
		'assert\s*\(',
		
		// Suspicious JavaScript
		'document\.write\s*\(',
		'document\.cookie',
		'window\.location\s*=',
		'atob\s*\(',  // base64 decode in JS
		
		// Known malware patterns
		'<script[^>]*src=["\']https?://[^"\']*\.ru["\']',  // Russian domains
		'<iframe[^>]*src=["\']https?://[^"\']*\.(ru|cn|tk)["\']',  // Suspicious TLDs
		
		// PHP backdoor patterns
		'system\s*\(',
		'exec\s*\(',
		'shell_exec\s*\(',
		'passthru\s*\(',
		'proc_open\s*\(',
	);

	/**
	 * Whitelisted domains (won't flag these)
	 */
	private static $whitelist = array(
		'youtube.com',
		'youtu.be',
		'vimeo.com',
		'google.com',
		'googleapis.com',
		'gstatic.com',
		'facebook.com',
		'twitter.com',
		'instagram.com',
		'cloudflare.com',
		'jquery.com',
		'wordpress.org',
		'wp.com',
	);

	/**
	 * Scan database tables
	 *
	 * @param int $batch_size Number of rows per batch
	 * @param int $offset Starting offset
	 * @return array Results
	 */
	public static function scan_batch( $batch_size = 50, $offset = 0 ) {
		global $wpdb;
		$results = array();

		// Scan wp_posts (exclude revisions and auto-drafts)
		$posts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content, post_excerpt 
				FROM {$wpdb->posts} 
				WHERE post_status NOT IN ('trash', 'auto-draft', 'inherit') 
				AND post_type NOT IN ('revision', 'nav_menu_item', 'custom_css', 'customize_changeset')
				LIMIT %d OFFSET %d",
				$batch_size,
				$offset
			)
		);

		foreach ( $posts as $post ) {
			// Check post_content - can return multiple threats
			$threats = self::check_content( $post->post_content );
			foreach ( $threats as $threat ) {
				$results[] = array(
					'type'     => 'post_content',
					'id'       => $post->ID,
					'title'    => $post->post_title,
					'location' => "Post #{$post->ID}: {$post->post_title}",
					'pattern'  => $threat['pattern'],
					'matched'  => $threat['matched'],
					'severity' => $threat['severity'],
				);
			}

			// Check post_excerpt
			$threats = self::check_content( $post->post_excerpt );
			foreach ( $threats as $threat ) {
				$results[] = array(
					'type'     => 'post_excerpt',
					'id'       => $post->ID,
					'title'    => $post->post_title,
					'location' => "Post Excerpt #{$post->ID}",
					'pattern'  => $threat['pattern'],
					'matched'  => $threat['matched'],
					'severity' => $threat['severity'],
				);
			}
		}

		return $results;
	}

	/**
	 * Scan comments
	 *
	 * @param int $batch_size Number of rows per batch
	 * @param int $offset Starting offset
	 * @return array Results
	 */
	public static function scan_comments_batch( $batch_size = 100, $offset = 0 ) {
		global $wpdb;
		$results = array();

		$comments = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT comment_ID, comment_author, comment_content 
				FROM {$wpdb->comments} 
				WHERE comment_approved != 'trash' 
				LIMIT %d OFFSET %d",
				$batch_size,
				$offset
			)
		);

		foreach ( $comments as $comment ) {
			$threats = self::check_content( $comment->comment_content );
			foreach ( $threats as $threat ) {
				$results[] = array(
					'type'     => 'comment_content',
					'id'       => $comment->comment_ID,
					'title'    => "Comment by {$comment->comment_author}",
					'location' => "Comment #{$comment->comment_ID}",
					'pattern'  => $threat['pattern'],
					'matched'  => $threat['matched'],
					'severity' => $threat['severity'],
				);
			}
		}

		return $results;
	}

	/**
	 * Scan options table
	 *
	 * @param int $batch_size Number of rows per batch
	 * @param int $offset Starting offset
	 * @return array Results
	 */
	public static function scan_options_batch( $batch_size = 50, $offset = 0 ) {
		global $wpdb;
		$results = array();

		$options = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_id, option_name, option_value 
				FROM {$wpdb->options} 
				WHERE option_value LIKE '%<%' 
				OR option_value LIKE '%eval%' 
				OR option_value LIKE '%base64%'
				LIMIT %d OFFSET %d",
				$batch_size,
				$offset
			)
		);

		foreach ( $options as $option ) {
			$threats = self::check_content( $option->option_value );
			foreach ( $threats as $threat ) {
				$results[] = array(
					'type'     => 'option_value',
					'id'       => $option->option_id,
					'title'    => $option->option_name,
					'location' => "Option: {$option->option_name}",
					'pattern'  => $threat['pattern'],
					'matched'  => $threat['matched'],
					'severity' => $threat['severity'],
				);
			}
		}

		return $results;
	}

	/**
	 * Check content for malicious patterns - returns ALL matches
	 *
	 * @param string $content Content to check
	 * @return array Array of threat details
	 */
	private static function check_content( $content ) {
		$threats = array();
		
		if ( empty( $content ) ) {
			return $threats;
		}

		// Check for suspicious scripts (find ALL scripts)
		if ( preg_match_all( '/<script[^>]*>(.*?)<\/script>/is', $content, $script_matches, PREG_SET_ORDER ) ) {
			$suspicious_script_patterns = array( 'eval\(', 'atob\(', 'document\.write\(', 'document\.cookie', 'base64_decode', 'fromCharCode' );
			
			foreach ( $script_matches as $script_match ) {
				$script_content = isset( $script_match[1] ) ? $script_match[1] : '';
				
				foreach ( $suspicious_script_patterns as $sus_pattern ) {
					if ( preg_match( '/' . $sus_pattern . '/i', $script_content ) ) {
						$threats[] = array(
							'pattern'  => 'Suspicious script content',
							'matched'  => isset( $script_match[0] ) ? substr( $script_match[0], 0, 100 ) : 'Unknown',
							'severity' => 'critical',
						);
						break; // Only report once per script
					}
				}
			}
		}
		
		// Check for iframes from suspicious domains (find ALL iframes)
		if ( preg_match_all( '/<iframe[^>]*src=["\']([^"\']+)["\'][^>]*>/i', $content, $iframe_matches, PREG_SET_ORDER ) ) {
			foreach ( $iframe_matches as $iframe_match ) {
				$iframe_src = isset( $iframe_match[1] ) ? $iframe_match[1] : '';
				
				// Check if it's whitelisted
				$is_safe = false;
				foreach ( self::$whitelist as $domain ) {
					if ( stripos( $iframe_src, $domain ) !== false ) {
						$is_safe = true;
						break;
					}
				}
				
				// Flag iframes from suspicious TLDs
				if ( ! $is_safe && preg_match( '/\.(ru|cn|tk|ml|ga|cf|gq)($|\/)/i', $iframe_src ) ) {
					$threats[] = array(
						'pattern'  => 'Suspicious iframe domain',
						'matched'  => isset( $iframe_match[0] ) ? $iframe_match[0] : 'Unknown',
						'severity' => 'high',
					);
				}
			}
		}

		// Check for other malicious patterns (skip if already found in scripts)
		$already_found = array();
		foreach ( $threats as $threat ) {
			$already_found[] = strtolower( $threat['matched'] );
		}
		
		foreach ( self::$patterns as $pattern ) {
			if ( preg_match( '/' . $pattern . '/i', $content, $matches ) ) {
				$matched = isset( $matches[0] ) ? $matches[0] : 'Unknown';
				
				// Skip if this was already detected in script check
				$skip = false;
				foreach ( $already_found as $found ) {
					if ( stripos( $found, $matched ) !== false ) {
						$skip = true;
						break;
					}
				}
				
				if ( ! $skip ) {
					$threats[] = array(
						'pattern'  => $pattern,
						'matched'  => $matched,
						'severity' => self::get_severity( $pattern ),
					);
				}
			}
		}

		return $threats;
	}

	/**
	 * Get severity level for pattern
	 *
	 * @param string $pattern Pattern matched
	 * @return string Severity level
	 */
	private static function get_severity( $pattern ) {
		$critical = array( 'eval', 'base64_decode', 'system', 'exec', 'shell_exec' );
		
		foreach ( $critical as $crit ) {
			if ( stripos( $pattern, $crit ) !== false ) {
				return 'critical';
			}
		}

		return 'high';
	}

	/**
	 * Get total counts for progress tracking
	 *
	 * @return array Counts
	 */
	public static function get_counts() {
		global $wpdb;

		return array(
			'posts'    => $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status NOT IN ('trash', 'auto-draft', 'inherit') AND post_type NOT IN ('revision', 'nav_menu_item', 'custom_css', 'customize_changeset')" ),
			'comments' => $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved != 'trash'" ),
			'options'  => $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options}" ),
		);
	}
}
