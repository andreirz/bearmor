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
		
		// Separate by severity
		$high_count = 0;
		$medium_count = 0;
		$high_threats = array();
		$medium_threats = array();
		
		if ( ! empty( $malware['details'] ) ) {
			foreach ( $malware['details'] as $threat ) {
				if ( $threat['severity'] === 'high' || $threat['severity'] === 'critical' ) {
					$high_count++;
					if ( count( $high_threats ) < 5 ) {
						$high_threats[] = $threat;
					}
				} else {
					$medium_count++;
					if ( count( $medium_threats ) < 5 ) {
						$medium_threats[] = $threat;
					}
				}
			}
		}
		
		$summary .= "MALWARE THREATS: {$malware['count']} files detected ({$high_count} HIGH, {$medium_count} MEDIUM)\n\n";
		
		// HIGH SEVERITY
		$summary .= "HIGH SEVERITY ({$high_count} files):\n";
		$summary .= "Examples: eval(\$_POST['cmd']), system(\$_GET['c']), base64+eval combo\n";
		if ( $high_count > 0 && ! empty( $high_threats ) ) {
			foreach ( $high_threats as $threat ) {
				$pattern = ! empty( $threat['pattern_name'] ) ? $threat['pattern_name'] : $threat['pattern_id'];
				$summary .= "- {$threat['file_path']} (line {$threat['line_number']}): {$pattern}\n";
				// Add 3 lines of code context if available
				if ( ! empty( $threat['code_snippet'] ) ) {
					$lines = explode( "\n", $threat['code_snippet'] );
					foreach ( $lines as $line ) {
						$summary .= "  " . trim( $line ) . "\n";
					}
				}
			}
			if ( $high_count > 5 ) {
				$summary .= "... and " . ( $high_count - 5 ) . " more HIGH threats\n";
			}
		} else {
			$summary .= "(none)\n";
		}
		$summary .= "\n";
		
		// MEDIUM SEVERITY
		$summary .= "MEDIUM SEVERITY ({$medium_count} files):\n";
		$summary .= "Examples: base64_decode alone, exec in plugins, fsockopen for APIs\n";
		if ( $medium_count > 0 && ! empty( $medium_threats ) ) {
			foreach ( $medium_threats as $threat ) {
				$pattern = ! empty( $threat['pattern_name'] ) ? $threat['pattern_name'] : $threat['pattern_id'];
				$summary .= "- {$threat['file_path']} (line {$threat['line_number']}): {$pattern}\n";
				// Add 3 lines of code context if available
				if ( ! empty( $threat['code_snippet'] ) ) {
					$lines = explode( "\n", $threat['code_snippet'] );
					$line_count = 0;
					foreach ( $lines as $line ) {
						if ( $line_count++ >= 3 ) break; // Limit to 3 lines for MEDIUM
						$summary .= "  " . trim( $line ) . "\n";
					}
				}
			}
			if ( $medium_count > 5 ) {
				$summary .= "... and " . ( $medium_count - 5 ) . " more MEDIUM threats\n";
			}
		} else {
			$summary .= "(none)\n";
		}
		$summary .= "\n";

		// 2. FILE CHANGES - CATEGORIZED BY TYPE
		$file_changes = self::get_file_changes( $days );
		$summary .= "FILE CHANGES: {$file_changes['count']} files modified\n\n";
		
		if ( $file_changes['count'] > 0 && ! empty( $file_changes['details'] ) ) {
			// Categorize files
			$core_files = array();
			$plugin_files = array();
			$theme_files = array();
			$upload_files = array();
			
			foreach ( $file_changes['details'] as $change ) {
				$path = $change['file_path'];
				if ( strpos( $path, 'wp-admin/' ) === 0 || strpos( $path, 'wp-includes/' ) === 0 ) {
					$core_files[] = $change;
				} elseif ( strpos( $path, 'wp-content/plugins/' ) !== false ) {
					$plugin_files[] = $change;
				} elseif ( strpos( $path, 'wp-content/themes/' ) !== false ) {
					$theme_files[] = $change;
				} elseif ( strpos( $path, 'wp-content/uploads/' ) !== false ) {
					$upload_files[] = $change;
				}
			}
			
			// Core files
			$summary .= "CORE FILES (" . count( $core_files ) . "):\n";
			if ( count( $core_files ) > 0 ) {
				foreach ( array_slice( $core_files, 0, 3 ) as $change ) {
					$summary .= "- {$change['file_path']}\n";
				}
				if ( count( $core_files ) > 3 ) {
					$summary .= "... and " . ( count( $core_files ) - 3 ) . " more\n";
				}
			} else {
				$summary .= "(none)\n";
			}
			
			// Plugin files
			$summary .= "\nPLUGIN FILES (" . count( $plugin_files ) . "):\n";
			if ( count( $plugin_files ) > 0 ) {
				foreach ( array_slice( $plugin_files, 0, 5 ) as $change ) {
					$summary .= "- {$change['file_path']}\n";
				}
				if ( count( $plugin_files ) > 5 ) {
					$summary .= "... and " . ( count( $plugin_files ) - 5 ) . " more\n";
				}
			} else {
				$summary .= "(none)\n";
			}
			
			// Theme files
			$summary .= "\nTHEME FILES (" . count( $theme_files ) . "):\n";
			if ( count( $theme_files ) > 0 ) {
				foreach ( array_slice( $theme_files, 0, 3 ) as $change ) {
					$summary .= "- {$change['file_path']}\n";
				}
				if ( count( $theme_files ) > 3 ) {
					$summary .= "... and " . ( count( $theme_files ) - 3 ) . " more\n";
				}
			} else {
				$summary .= "(none)\n";
			}
			
			// Uploads
			$summary .= "\nUPLOADS (" . count( $upload_files ) . "):\n";
			if ( count( $upload_files ) > 0 ) {
				foreach ( array_slice( $upload_files, 0, 3 ) as $change ) {
					$summary .= "- {$change['file_path']}\n";
				}
				if ( count( $upload_files ) > 3 ) {
					$summary .= "... and " . ( count( $upload_files ) - 3 ) . " more\n";
				}
			} else {
				$summary .= "(none)\n";
			}
			
			$summary .= "\nNote: Plugin updates rebuild baseline automatically.\n";
		} elseif ( $file_changes['count'] > 0 ) {
			$summary .= "WARNING: {$file_changes['count']} files modified (run File Monitor for details)\n";
		} else {
			$summary .= "No changes detected\n";
		}
		$summary .= "\n";

		// 3. VULNERABILITIES
		$vulns = self::get_vulnerabilities();
		
		// Separate by severity
		$critical_vulns = array();
		$medium_vulns = array();
		if ( ! empty( $vulns['all'] ) ) {
			foreach ( $vulns['all'] as $vuln ) {
				if ( $vuln['severity'] === 'critical' || $vuln['severity'] === 'high' ) {
					$critical_vulns[] = $vuln;
				} else {
					$medium_vulns[] = $vuln;
				}
			}
		}
		
		$summary .= "VULNERABILITIES: {$vulns['count']} found (" . count( $critical_vulns ) . " CRITICAL, " . count( $medium_vulns ) . " MEDIUM)\n\n";
		
		if ( $vulns['count'] > 0 ) {
			// CRITICAL
			$summary .= "CRITICAL (" . count( $critical_vulns ) . "):\n";
			if ( count( $critical_vulns ) > 0 ) {
				foreach ( array_slice( $critical_vulns, 0, 3 ) as $vuln ) {
					$summary .= "- {$vuln['name']} {$vuln['version']} → {$vuln['fixed_version']} ({$vuln['severity']})\n";
				}
				if ( count( $critical_vulns ) > 3 ) {
					$summary .= "... and " . ( count( $critical_vulns ) - 3 ) . " more\n";
				}
			} else {
				$summary .= "(none)\n";
			}
			
			// MEDIUM
			$summary .= "\nMEDIUM (" . count( $medium_vulns ) . "):\n";
			if ( count( $medium_vulns ) > 0 ) {
				foreach ( array_slice( $medium_vulns, 0, 5 ) as $vuln ) {
					$summary .= "- {$vuln['name']} {$vuln['version']} → {$vuln['fixed_version']}\n";
				}
				if ( count( $medium_vulns ) > 5 ) {
					$summary .= "... and " . ( count( $medium_vulns ) - 5 ) . " more\n";
				}
			} else {
				$summary .= "(none)\n";
			}
		} else {
			$summary .= "All plugins/themes up to date\n";
		}
		$summary .= "\n";

		// 4. LOGIN ACTIVITY
		$login = self::get_login_activity( $days );
		$summary .= "LOGIN ATTEMPTS: {$login['total']} ({$login['failed']} failed, " . ( $login['total'] - $login['failed'] ) . " successful)\n\n";
		if ( $login['failed'] > 0 && ! empty( $login['failed_details'] ) ) {
			$summary .= "Failed attempts (top 5):\n";
			foreach ( $login['failed_details'] as $attempt ) {
				$summary .= "- \"{$attempt['username']}\" from {$attempt['ip']} ({$attempt['count']} attempts)\n";
			}
			$summary .= "\nInterpretation: Failed attempts are normal bot activity. Firewall blocking effectively. 1000+ failed = working protection (good).\n";
		} else {
			$summary .= "All login attempts successful\n";
		}
		$summary .= "\n";

		// 5. FIREWALL BLOCKS
		$firewall = self::get_firewall_blocks( $days );
		$summary .= "FIREWALL BLOCKS: {$firewall['count']} attacks (last 24h)\n\n";
		if ( $firewall['count'] > 0 ) {
			if ( ! empty( $firewall['details'] ) ) {
				// Count attack types
				$attack_types = array();
				foreach ( $firewall['details'] as $block ) {
					$reason = ! empty( $block['reason'] ) ? $block['reason'] : 'Unknown';
					if ( ! isset( $attack_types[ $reason ] ) ) {
						$attack_types[ $reason ] = 0;
					}
					$attack_types[ $reason ]++;
				}
				
				$summary .= "Attack types:\n";
				foreach ( $attack_types as $type => $count ) {
					$summary .= "- {$type}: {$count}\n";
				}
			} else {
				$summary .= "{$firewall['count']} malicious requests blocked\n";
			}
			$summary .= "\nInterpretation: Blocks are good - firewall protecting site. 1-100/day = normal, 1000+ = active attack.\n";
		} else {
			$summary .= "No attacks detected\n";
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

		// 7. LOGIN ANOMALIES
		$anomalies = self::get_login_anomalies( $days );
		if ( $anomalies['count'] > 0 ) {
			$summary .= "LOGIN ANOMALIES: {$anomalies['count']} pattern detected\n\n";
			if ( ! empty( $anomalies['details'] ) ) {
				foreach ( $anomalies['details'] as $idx => $anomaly ) {
					if ( $idx >= 3 ) break; // Limit to 3
					$summary .= ( $idx + 1 ) . ". {$anomaly['anomaly_type']}\n";
					$summary .= "   {$anomaly['description']}\n";
				}
				$summary .= "\nInterpretation: New country logins may indicate compromise.\n";
			} else {
				$summary .= "Unusual login patterns detected - review Security Logs\n";
			}
			$summary .= "\n";
		}

		// 8. DEEP SCAN RESULTS
		$deep_scan = self::get_deep_scan_results();
		if ( $deep_scan['total'] > 0 ) {
			$summary .= "DEEP SCAN THREATS: {$deep_scan['total']} found ({$deep_scan['database']['count']} database, {$deep_scan['uploads']['count']} files)\n\n";
			
			// Database threats
			if ( $deep_scan['database']['count'] > 0 ) {
				$summary .= "DATABASE ({$deep_scan['database']['count']}):\n";
				if ( ! empty( $deep_scan['database']['details'] ) ) {
					foreach ( $deep_scan['database']['details'] as $idx => $threat ) {
						if ( $idx >= 3 ) break; // Limit to 3
						$location = ! empty( $threat['location'] ) ? $threat['location'] : $threat['item_type'];
						$pattern = ! empty( $threat['pattern'] ) ? $threat['pattern'] : 'Unknown';
						$summary .= ( $idx + 1 ) . ". {$location}\n";
						$summary .= "   Pattern: {$pattern}\n";
						if ( ! empty( $threat['matched_code'] ) ) {
							$preview = substr( $threat['matched_code'], 0, 60 );
							$summary .= "   Preview: {$preview}...\n";
						}
					}
					if ( $deep_scan['database']['count'] > 3 ) {
						$summary .= "... and " . ( $deep_scan['database']['count'] - 3 ) . " more\n";
					}
				}
			}
			
			// Uploads threats
			if ( $deep_scan['uploads']['count'] > 0 ) {
				$summary .= "\nUPLOADS ({$deep_scan['uploads']['count']}):\n";
				if ( ! empty( $deep_scan['uploads']['details'] ) ) {
					foreach ( array_slice( $deep_scan['uploads']['details'], 0, 5 ) as $threat ) {
						$summary .= "{$threat['location']}\n";
						
						// Try to read actual file content for preview
						$file_path = ABSPATH . $threat['location'];
						$content_preview = '';
						if ( file_exists( $file_path ) && is_readable( $file_path ) ) {
							$file_size = filesize( $file_path );
							$summary .= "   Size: {$file_size} bytes\n";
							
							if ( $file_size < 1000 ) {
								$content = file_get_contents( $file_path );
								$content_preview = substr( $content, 0, 60 );
							} else {
								$content_preview = substr( file_get_contents( $file_path, false, null, 0, 60 ), 0, 60 );
							}
							$summary .= "   Content: " . trim( $content_preview ) . "...\n";
						} else {
							$summary .= "   Content: (file not readable)\n";
						}
					}
					if ( $deep_scan['uploads']['count'] > 5 ) {
						$summary .= "... and " . ( $deep_scan['uploads']['count'] - 5 ) . " more\n";
					}
				}
			}
			$summary .= "\nNote: \"Silence is golden\" files are WordPress placeholders (safe). PHP in plugin folders often legitimate.\n";
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
				"SELECT ip_address, request_uri, rule_matched as reason 
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
			WHERE status = 'active'"
		);

		// Get ALL vulnerabilities, not just top 3
		$all = $wpdb->get_results(
			"SELECT item_name as name, item_version as version, fixed_in as fixed_version, severity 
			FROM {$wpdb->prefix}bearmor_vulnerabilities 
			WHERE status = 'active'
			ORDER BY 
				CASE severity 
					WHEN 'critical' THEN 1 
					WHEN 'high' THEN 2 
					WHEN 'medium' THEN 3 
					ELSE 4 
				END",
			ARRAY_A
		);

		return array(
			'count' => intval( $count ),
			'all'   => $all,
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
