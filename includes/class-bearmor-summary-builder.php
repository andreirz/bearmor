<?php
/**
 * Summary Builder for AI Analysis
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Summary_Builder {

	/**
	 * Build security summary for OpenAI (max 1024 chars per section)
	 *
	 * @param int $days Number of days to look back
	 * @return string Formatted summary text
	 */
	public static function build_summary( $days = 7 ) {
		global $wpdb;
		
		$summary = "SECURITY REPORT - Recent Activity\n";
		$summary .= str_repeat( '=', 60 ) . "\n\n";

		// 1. MALWARE THREATS - SHOW ACTUAL CONTEXT!
		$malware = self::get_malware_detections( $days );
		$summary .= "MALWARE THREATS: {$malware['count']} files infected\n";
		if ( $malware['count'] > 0 ) {
			if ( ! empty( $malware['details'] ) ) {
				foreach ( $malware['details'] as $idx => $threat ) {
					if ( $idx >= 10 ) break; // Limit to 10 for AI
					$file = basename( $threat['file_path'] );
					$pattern = ! empty( $threat['pattern_name'] ) ? $threat['pattern_name'] : $threat['pattern_id'];
					$code = ! empty( $threat['matched_text'] ) ? $threat['matched_text'] : $threat['code_snippet'];
					$code_preview = $code ? ' - "' . substr( $code, 0, 50 ) . '..."' : '';
					$summary .= "   - {$file} (line {$threat['line_number']}): {$pattern}{$code_preview}\n";
				}
				if ( $malware['count'] > 10 ) {
					$summary .= "   ... and " . ( $malware['count'] - 10 ) . " more infected files\n";
				}
			} else {
				$summary .= "   WARNING: {$malware['count']} threats detected - run Malware Scanner for details\n";
			}
		} else {
			$summary .= "   No threats detected\n";
		}
		$summary .= "\n";

		// 2. FILE CHANGES - SHOW ACTUAL FILES
		$file_changes = self::get_file_changes( $days );
		$summary .= "FILE CHANGES: {$file_changes['count']} files modified\n";
		if ( $file_changes['count'] > 0 && ! empty( $file_changes['details'] ) ) {
			foreach ( $file_changes['details'] as $idx => $change ) {
				if ( $idx >= 8 ) break; // Limit to 8
				$summary .= "   - {$change['file']}: {$change['change_type']}\n";
			}
			if ( $file_changes['count'] > 8 ) {
				$summary .= "   ... and " . ( $file_changes['count'] - 8 ) . " more files\n";
			}
		} elseif ( $file_changes['count'] > 0 ) {
			$summary .= "   WARNING: {$file_changes['count']} files modified (run File Monitor for details)\n";
		} else {
			$summary .= "   No changes detected\n";
		}
		$summary .= "\n";

		// 3. VULNERABILITIES
		$vulns = self::get_vulnerabilities();
		$summary .= "VULNERABILITIES: {$vulns['count']}\n";
		if ( ! empty( $vulns['critical'] ) ) {
			foreach ( $vulns['critical'] as $vuln ) {
				$summary .= "   - {$vuln['name']} v{$vuln['version']} (needs v{$vuln['fixed_version']}) - {$vuln['severity']}\n";
			}
		} else {
			$summary .= "   All plugins/themes up to date\n";
		}
		$summary .= "\n";

		// 4. LOGIN ACTIVITY
		$login = self::get_login_activity( $days );
		$summary .= "LOGIN ATTEMPTS: {$login['total']} ({$login['failed']} failed)\n";
		if ( $login['failed'] > 0 && ! empty( $login['failed_details'] ) ) {
			$summary .= "   Failed attempts:\n";
			foreach ( $login['failed_details'] as $attempt ) {
				$summary .= "   - {$attempt['username']} from {$attempt['ip']} ({$attempt['count']}x)\n";
			}
		} else {
			$summary .= "   All login attempts successful\n";
		}
		$summary .= "\n";

		// 5. FIREWALL BLOCKS - SHOW ATTACK TYPES
		$firewall = self::get_firewall_blocks( $days );
		$summary .= "FIREWALL BLOCKS: {$firewall['count']} attacks blocked\n";
		if ( $firewall['count'] > 0 && ! empty( $firewall['details'] ) ) {
			foreach ( $firewall['details'] as $idx => $block ) {
				if ( $idx >= 6 ) break; // Limit to 6
				$summary .= "   - {$block['reason']}: {$block['uri']}\n";
			}
			if ( $firewall['count'] > 6 ) {
				$summary .= "   ... and " . ( $firewall['count'] - 6 ) . " more attacks\n";
			}
		} elseif ( $firewall['count'] > 0 ) {
			$summary .= "   WARNING: {$firewall['count']} malicious requests blocked\n";
		} else {
			$summary .= "   No attacks detected\n";
		}
		$summary .= "\n";

		// 6. SECURITY ACTIVITY (plugins/themes activated/deactivated, settings changed)
		$activity = self::get_security_activity( $days );
		if ( $activity['count'] > 0 ) {
			$summary .= "SECURITY ACTIVITY: {$activity['count']} events\n";
			if ( ! empty( $activity['details'] ) ) {
				foreach ( $activity['details'] as $event ) {
					$summary .= "   - {$event['action']}: {$event['description']}\n";
				}
			}
			$summary .= "\n";
		}

		// 7. LOGIN ANOMALIES - SHOW ACTUAL ANOMALIES
		$anomalies = self::get_login_anomalies( $days );
		if ( $anomalies['count'] > 0 ) {
			$summary .= "LOGIN ANOMALIES: {$anomalies['count']} unusual patterns\n";
			if ( ! empty( $anomalies['details'] ) ) {
				foreach ( $anomalies['details'] as $idx => $anomaly ) {
					if ( $idx >= 5 ) break; // Limit to 5
					$summary .= "   - {$anomaly['anomaly_type']}: {$anomaly['description']}\n";
				}
			} else {
				$summary .= "   Unusual login patterns detected - review Security Logs\n";
			}
			$summary .= "\n";
		}

		// 8. DEEP SCAN RESULTS - DATABASE & UPLOADS
		$deep_scan = self::get_deep_scan_results();
		if ( $deep_scan['total'] > 0 ) {
			$summary .= "DEEP SCAN THREATS: {$deep_scan['total']} threats found\n";
			
			// Database threats
			if ( $deep_scan['database']['count'] > 0 ) {
				$summary .= "   Database: {$deep_scan['database']['count']} infected entries\n";
				if ( ! empty( $deep_scan['database']['details'] ) ) {
					foreach ( $deep_scan['database']['details'] as $idx => $threat ) {
						if ( $idx >= 5 ) break; // Limit to 5
						$location = ! empty( $threat['location'] ) ? $threat['location'] : $threat['item_type'];
						$pattern = ! empty( $threat['pattern'] ) ? $threat['pattern'] : 'Unknown';
						$summary .= "      - {$location}: {$pattern}\n";
					}
					if ( $deep_scan['database']['count'] > 5 ) {
						$summary .= "      ... and " . ( $deep_scan['database']['count'] - 5 ) . " more database threats\n";
					}
				}
			}
			
			// Uploads threats
			if ( $deep_scan['uploads']['count'] > 0 ) {
				$summary .= "   Uploads: {$deep_scan['uploads']['count']} malicious files\n";
				if ( ! empty( $deep_scan['uploads']['details'] ) ) {
					foreach ( $deep_scan['uploads']['details'] as $idx => $threat ) {
						if ( $idx >= 5 ) break; // Limit to 5
						$file = basename( $threat['location'] );
						$pattern = ! empty( $threat['pattern'] ) ? $threat['pattern'] : 'Suspicious file';
						$summary .= "      - {$file}: {$pattern}\n";
					}
					if ( $deep_scan['uploads']['count'] > 5 ) {
						$summary .= "      ... and " . ( $deep_scan['uploads']['count'] - 5 ) . " more malicious files\n";
					}
				}
			}
			$summary .= "\n";
		}

		return $summary;
	}

	/**
	 * Get human-readable pattern name
	 */
	private static function get_pattern_name( $pattern_id ) {
		$patterns = array(
			'shell_exec'     => 'Shell command execution',
			'eval'           => 'Code evaluation (eval)',
			'base64_decode'  => 'Base64 encoded code',
			'fsockopen'      => 'Network socket connection',
			'curl_exec'      => 'Remote HTTP request',
			'file_get_contents' => 'Remote file access',
			'system'         => 'System command',
			'exec'           => 'Command execution',
			'passthru'       => 'Command passthrough',
			'proc_open'      => 'Process execution',
			'popen'          => 'Pipe open',
			'assert'         => 'Code assertion',
			'preg_replace'   => 'Regex code execution',
			'create_function' => 'Dynamic function creation',
			'include'        => 'File inclusion',
			'require'        => 'File requirement',
		);
		
		return isset( $patterns[ $pattern_id ] ) ? $patterns[ $pattern_id ] : $pattern_id;
	}

	/**
	 * Get file changes with details
	 */
	private static function get_file_changes( $days ) {
		global $wpdb;
		
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_changes 
				WHERE detected_at >= DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);

		$details = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT file_path, change_type, detected_at 
				FROM {$wpdb->prefix}bearmor_file_changes 
				WHERE detected_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				ORDER BY detected_at DESC LIMIT 10",
				$days
			),
			ARRAY_A
		);

		// Shorten file paths
		foreach ( $details as &$detail ) {
			$detail['file'] = basename( $detail['file_path'] );
		}

		return array(
			'count'   => intval( $count ),
			'details' => $details,
		);
	}

	/**
	 * Get malware detections from CORRECT TABLE with CORRECT COLUMNS
	 */
	private static function get_malware_detections( $days ) {
		global $wpdb;
		
		$table = $wpdb->prefix . 'bearmor_malware_detections';
		
		// Count ALL threats
		$count = $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		// Count by severity
		$status_counts = $wpdb->get_results(
			"SELECT severity, COUNT(*) as count FROM {$table} GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END",
			ARRAY_A
		);

		// Get detailed threat information with CORRECT column names
		$details = $wpdb->get_results(
			"SELECT file_path, pattern_id, pattern_name, matched_text, code_snippet, severity, line_number 
			FROM {$table} 
			ORDER BY 
				CASE severity 
					WHEN 'critical' THEN 1 
					WHEN 'high' THEN 2 
					WHEN 'medium' THEN 3 
					ELSE 4 
				END,
				detected_at DESC
			LIMIT 15",
			ARRAY_A
		);

		return array(
			'count'         => intval( $count ),
			'status_counts' => $status_counts,
			'details'       => $details,
		);
	}

	/**
	 * Get login activity with failed attempt details
	 */
	private static function get_login_activity( $days ) {
		global $wpdb;
		
		$total = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_attempts 
				WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);

		$failed = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_attempts 
				WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				AND success = 0",
				$days
			)
		);

		// Get failed login details
		$failed_details = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT username, ip_address, COUNT(*) as count 
				FROM {$wpdb->prefix}bearmor_login_attempts 
				WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				AND success = 0
				GROUP BY username, ip_address 
				ORDER BY count DESC LIMIT 5",
				$days
			),
			ARRAY_A
		);

		// Anonymize IPs
		foreach ( $failed_details as &$detail ) {
			$parts = explode( '.', $detail['ip_address'] );
			if ( count( $parts ) === 4 ) {
				$detail['ip'] = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.x';
			} else {
				$detail['ip'] = 'xxx.xxx.xxx.x';
			}
		}

		return array(
			'total'          => intval( $total ),
			'failed'         => intval( $failed ),
			'failed_details' => $failed_details,
		);
	}

	/**
	 * Get firewall blocks with details
	 */
	private static function get_firewall_blocks( $days ) {
		global $wpdb;
		
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_firewall_blocks 
				WHERE blocked_at >= DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);

		// Get actual block details (not just counts)
		$details = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip_address, request_uri, reason 
				FROM {$wpdb->prefix}bearmor_firewall_blocks 
				WHERE blocked_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				ORDER BY blocked_at DESC LIMIT 10",
				$days
			),
			ARRAY_A
		);

		// Anonymize IPs and shorten URIs
		foreach ( $details as &$detail ) {
			$parts = explode( '.', $detail['ip_address'] );
			if ( count( $parts ) === 4 ) {
				$detail['ip'] = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.x';
			} else {
				$detail['ip'] = 'xxx.xxx.xxx.x';
			}
			$detail['uri'] = strlen( $detail['request_uri'] ) > 50 ? substr( $detail['request_uri'], 0, 50 ) . '...' : $detail['request_uri'];
		}

		return array(
			'count'   => intval( $count ),
			'details' => $details,
		);
	}

	/**
	 * Get vulnerabilities
	 */
	private static function get_vulnerabilities() {
		global $wpdb;
		
		$count = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_vulnerabilities 
			WHERE status = 'open'"
		);

		$critical = $wpdb->get_results(
			"SELECT item_name as name, current_version as version, fixed_version, severity 
			FROM {$wpdb->prefix}bearmor_vulnerabilities 
			WHERE status = 'open'
			ORDER BY 
				CASE severity 
					WHEN 'critical' THEN 1 
					WHEN 'high' THEN 2 
					WHEN 'medium' THEN 3 
					ELSE 4 
				END
			LIMIT 3",
			ARRAY_A
		);

		return array(
			'count'    => intval( $count ),
			'critical' => $critical,
		);
	}

	/**
	 * Get security activity (plugin/theme changes, settings)
	 */
	private static function get_security_activity( $days ) {
		global $wpdb;
		
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_activity_log 
				WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %d DAY)
				AND action IN ('plugin_activated', 'plugin_deactivated', 'theme_switched', 'user_created', 'user_deleted', 'settings_changed')",
				$days
			)
		);

		$details = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT action, description, username 
				FROM {$wpdb->prefix}bearmor_activity_log 
				WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %d DAY)
				AND action IN ('plugin_activated', 'plugin_deactivated', 'theme_switched', 'user_created', 'user_deleted', 'settings_changed')
				ORDER BY timestamp DESC LIMIT 10",
				$days
			),
			ARRAY_A
		);

		return array(
			'count'   => intval( $count ),
			'details' => $details,
		);
	}

	/**
	 * Get login anomalies
	 */
	private static function get_login_anomalies( $days ) {
		global $wpdb;
		
		$table = $wpdb->prefix . 'bearmor_login_anomalies';
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" );
		
		if ( ! $table_exists ) {
			return array( 'count' => 0, 'details' => array() );
		}
		
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} 
				WHERE detected_at >= DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);

		$details = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT anomaly_type, description, anomaly_score 
				FROM {$table} 
				WHERE detected_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				ORDER BY anomaly_score DESC LIMIT 5",
				$days
			),
			ARRAY_A
		);

		return array(
			'count'   => intval( $count ),
			'details' => $details,
		);
	}

	/**
	 * Get deep scan results (database + uploads)
	 */
	private static function get_deep_scan_results() {
		global $wpdb;
		
		$table = $wpdb->prefix . 'bearmor_deep_scan_results';
		
		// Check if table exists
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" );
		if ( ! $table_exists ) {
			return array(
				'total'    => 0,
				'database' => array( 'count' => 0, 'details' => array() ),
				'uploads'  => array( 'count' => 0, 'details' => array() ),
			);
		}
		
		// Get database threats (pending only)
		$db_count = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$table} 
			WHERE scan_type = 'database' AND status = 'pending'"
		);
		
		$db_details = $wpdb->get_results(
			"SELECT location, pattern, matched_code, severity, item_type 
			FROM {$table} 
			WHERE scan_type = 'database' AND status = 'pending'
			ORDER BY 
				CASE severity 
					WHEN 'critical' THEN 1 
					WHEN 'high' THEN 2 
					WHEN 'medium' THEN 3 
					ELSE 4 
				END,
				detected_at DESC
			LIMIT 10",
			ARRAY_A
		);
		
		// Get uploads threats (pending only)
		$uploads_count = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$table} 
			WHERE scan_type = 'uploads' AND status = 'pending'"
		);
		
		$uploads_details = $wpdb->get_results(
			"SELECT location, pattern, matched_code, severity 
			FROM {$table} 
			WHERE scan_type = 'uploads' AND status = 'pending'
			ORDER BY 
				CASE severity 
					WHEN 'critical' THEN 1 
					WHEN 'high' THEN 2 
					WHEN 'medium' THEN 3 
					ELSE 4 
				END,
				detected_at DESC
			LIMIT 10",
			ARRAY_A
		);
		
		$total = intval( $db_count ) + intval( $uploads_count );
		
		return array(
			'total'    => $total,
			'database' => array(
				'count'   => intval( $db_count ),
				'details' => $db_details,
			),
			'uploads'  => array(
				'count'   => intval( $uploads_count ),
				'details' => $uploads_details,
			),
		);
	}
}
