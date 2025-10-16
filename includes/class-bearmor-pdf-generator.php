<?php
/**
 * PDF Report Generator
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_PDF_Generator {

	const REPORT_DIR = WP_CONTENT_DIR . '/bearmor-reports/';

	/**
	 * Generate PDF report
	 *
	 * @param int $days Number of days to include in report
	 * @return string|WP_Error File path or error
	 */
	public static function generate( $days = 7 ) {
		// Ensure report directory exists
		if ( ! file_exists( self::REPORT_DIR ) ) {
			wp_mkdir_p( self::REPORT_DIR );
		}

		// Collect data
		$data = self::collect_report_data( $days );

		// Generate filename
		$filename = 'bearmor-report-' . gmdate( 'Y-m-d-H-i-s' ) . '.html';
		$filepath = self::REPORT_DIR . $filename;

		// Generate HTML report (we'll use HTML to PDF conversion)
		$html = self::generate_html_report( $data );

		// Save HTML file
		file_put_contents( $filepath, $html );

		// Convert HTML to PDF using mPDF or similar
		$pdf_filepath = self::convert_to_pdf( $filepath, $data );

		if ( is_wp_error( $pdf_filepath ) ) {
			return $pdf_filepath;
		}

		// Return the file path (keep HTML file for viewing)
		return $pdf_filepath;
	}

	/**
	 * Collect all report data
	 *
	 * @param int $days Number of days
	 * @return array Report data
	 */
	private static function collect_report_data( $days ) {
		global $wpdb;

		$start_date = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $days * DAY_IN_SECONDS ) );

		return array(
			'site_name'       => get_bloginfo( 'name' ),
			'site_url'        => get_bloginfo( 'url' ),
			'report_date'     => gmdate( 'Y-m-d H:i:s' ),
			'date_range'      => $days . ' days',
			'security_score'  => self::get_security_score(),
			'file_changes'    => self::get_file_changes_count( $start_date ),
			'malware'         => self::get_malware_count( $start_date ),
			'vulnerabilities' => self::get_vulnerabilities_count(),
			'firewall_blocks' => self::get_firewall_blocks_count( $start_date ),
			'login_anomalies' => self::get_login_anomalies_count( $start_date ),
			'ai_analysis'     => self::get_latest_ai_analysis(),
		);
	}

	/**
	 * Generate HTML report
	 *
	 * @param array $data Report data
	 * @return string HTML content
	 */
	private static function generate_html_report( $data ) {
		ob_start();
		?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Bearmor Security Report</title>
	<style>
		body {
			font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			color: #333;
			line-height: 1.6;
			margin: 0;
			padding: 30px;
			background: #f5f5f5;
		}
		.header {
			background: linear-gradient(135deg, #8269FF 0%, #6B52E0 100%);
			color: white;
			padding: 50px 40px;
			text-align: center;
			border-radius: 12px;
			margin-bottom: 40px;
			box-shadow: 0 4px 15px rgba(130, 105, 255, 0.2);
		}
		.header h1 {
			margin: 0 0 15px 0;
			font-size: 36px;
			font-weight: 600;
		}
		.header p {
			margin: 5px 0;
			font-size: 14px;
			opacity: 0.95;
		}
		.section {
			margin-bottom: 40px;
			page-break-inside: avoid;
			background: white;
			padding: 30px;
			border-radius: 10px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.05);
		}
		.section h2 {
			font-size: 20px;
			color: #8269FF;
			border-bottom: 3px solid #8269FF;
			padding-bottom: 12px;
			margin: 0 0 25px 0;
			font-weight: 600;
		}
		.metrics-grid {
			display: grid;
			grid-template-columns: 1fr 1fr;
			gap: 20px;
		}
		.metric {
			padding: 20px;
			background: linear-gradient(135deg, #f8f7ff 0%, #f0edff 100%);
			border-radius: 8px;
			border-left: 5px solid #8269FF;
			transition: transform 0.2s;
		}
		.metric:hover {
			transform: translateY(-2px);
			box-shadow: 0 4px 12px rgba(130, 105, 255, 0.15);
		}
		.metric-value {
			font-size: 32px;
			font-weight: 700;
			color: #8269FF;
			margin: 0;
		}
		.metric-label {
			font-size: 13px;
			color: #666;
			margin-top: 8px;
			font-weight: 500;
		}
		.metric-detail {
			font-size: 12px;
			color: #999;
			margin-top: 5px;
			font-style: italic;
		}
		.status-good { border-left-color: #4CAF50; }
		.status-warning { border-left-color: #FF9800; }
		.status-critical { border-left-color: #F44336; }
		.ai-analysis {
			background: linear-gradient(135deg, #f0edff 0%, #e8e0ff 100%);
			border: 2px solid #8269FF;
			border-radius: 8px;
			padding: 25px;
			margin-top: 20px;
		}
		.ai-analysis h3 {
			margin: 0 0 15px 0;
			color: #8269FF;
			font-size: 16px;
		}
		.ai-analysis p {
			margin: 0 0 12px 0;
			line-height: 1.7;
			font-size: 14px;
		}
		.ai-analysis p:last-child {
			margin-bottom: 0;
		}
		.footer {
			margin-top: 50px;
			padding-top: 25px;
			border-top: 2px solid #ddd;
			font-size: 12px;
			color: #999;
			text-align: center;
		}
		.color-green { color: #4CAF50; font-weight: 600; }
		.color-yellow { color: #FF9800; font-weight: 600; }
		.color-red { color: #F44336; font-weight: 600; }
		@media print {
			body { background: white; padding: 0; }
			.section { box-shadow: none; page-break-inside: avoid; }
		}
	</style>
</head>
<body>
	<div class="header">
		<h1>🛡️ Bearmor Security Report</h1>
		<p><?php echo esc_html( $data['site_name'] ); ?></p>
		<p>Report Generated: <?php echo esc_html( $data['report_date'] ); ?> (Last <?php echo esc_html( $data['date_range'] ); ?>)</p>
	</div>

	<div class="section">
		<h2>Security Overview</h2>
		<div class="metrics-grid">
			<div class="metric <?php echo intval( $data['security_score'] ) >= 80 ? 'status-good' : ( intval( $data['security_score'] ) >= 50 ? 'status-warning' : 'status-critical' ); ?>">
				<div class="metric-value"><?php echo intval( $data['security_score'] ); ?>/100</div>
				<div class="metric-label">Security Score</div>
				<div class="metric-detail"><?php echo intval( $data['security_score'] ) >= 80 ? 'Excellent' : ( intval( $data['security_score'] ) >= 50 ? 'Needs Attention' : 'Critical' ); ?></div>
			</div>
			<div class="metric <?php echo intval( $data['malware'] ) === 0 ? 'status-good' : ( intval( $data['malware'] ) <= 5 ? 'status-warning' : 'status-critical' ); ?>">
				<div class="metric-value"><?php echo intval( $data['malware'] ); ?></div>
				<div class="metric-label">Malware Threats</div>
				<div class="metric-detail"><?php echo intval( $data['malware'] ) === 0 ? 'None detected' : 'Requires action'; ?></div>
			</div>
			<div class="metric <?php echo intval( $data['vulnerabilities'] ) === 0 ? 'status-good' : ( intval( $data['vulnerabilities'] ) <= 3 ? 'status-warning' : 'status-critical' ); ?>">
				<div class="metric-value"><?php echo intval( $data['vulnerabilities'] ); ?></div>
				<div class="metric-label">Vulnerabilities</div>
				<div class="metric-detail"><?php echo intval( $data['vulnerabilities'] ) === 0 ? 'All updated' : 'Update needed'; ?></div>
			</div>
			<div class="metric status-good">
				<div class="metric-value"><?php echo intval( $data['firewall_blocks'] ); ?></div>
				<div class="metric-label">Firewall Blocks</div>
				<div class="metric-detail">Attacks blocked</div>
			</div>
			<div class="metric">
				<div class="metric-value"><?php echo intval( $data['file_changes'] ); ?></div>
				<div class="metric-label">File Changes</div>
				<div class="metric-detail">Last 7 days</div>
			</div>
			<div class="metric">
				<div class="metric-value"><?php echo intval( $data['login_anomalies'] ); ?></div>
				<div class="metric-label">Login Anomalies</div>
				<div class="metric-detail">Detected</div>
			</div>
		</div>
	</div>

	<?php if ( $data['ai_analysis'] ) : ?>
		<div class="section">
			<h2>AI Security Analysis</h2>
			<div class="ai-analysis">
				<p><strong>Analysis from:</strong> <?php echo esc_html( $data['ai_analysis']['model_used'] ); ?></p>
				<p><?php echo nl2br( esc_html( $data['ai_analysis']['ai_response'] ) ); ?></p>
				<p><em>Generated: <?php echo esc_html( $data['ai_analysis']['created_at'] ); ?></em></p>
			</div>
		</div>
	<?php endif; ?>

	<div class="footer">
		<p>This report was automatically generated by Bearmor Security Plugin</p>
		<p><?php echo esc_html( $data['site_url'] ); ?></p>
	</div>
</body>
</html>
		<?php
		return ob_get_clean();
	}

	/**
	 * Convert HTML to PDF
	 *
	 * @param string $html_file HTML file path
	 * @param array  $data Report data
	 * @return string|WP_Error PDF file path or error
	 */
	private static function convert_to_pdf( $html_file, $data ) {
		// For now, save as HTML (viewable in browser)
		// Users can print to PDF from browser (Ctrl+P)
		
		$html_filename = 'bearmor-report-' . gmdate( 'Y-m-d-H-i-s' ) . '.html';
		$html_filepath = self::REPORT_DIR . $html_filename;

		// Read HTML content
		$html_content = file_get_contents( $html_file );

		// Save as HTML file
		file_put_contents( $html_filepath, $html_content );

		return $html_filepath;
	}

	/**
	 * Get security score
	 *
	 * @return int Score 0-100
	 */
	private static function get_security_score() {
		$score = 100;

		// Deduct points for issues
		$threats = Bearmor_Malware_Scanner::get_threats( 'pending' );
		$score -= count( $threats ) * 5;

		$vulns = Bearmor_Vulnerability_Scanner::get_vulnerabilities();
		$score -= count( $vulns ) * 3;

		return max( 0, min( 100, $score ) );
	}

	/**
	 * Get file changes count
	 *
	 * @param string $start_date Start date
	 * @return int Count
	 */
	private static function get_file_changes_count( $start_date ) {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_changes WHERE detected_at >= %s",
				$start_date
			)
		);
	}

	/**
	 * Get malware count
	 *
	 * @param string $start_date Start date
	 * @return int Count
	 */
	private static function get_malware_count( $start_date ) {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_malware_detections WHERE detected_at >= %s",
				$start_date
			)
		);
	}

	/**
	 * Get vulnerabilities count
	 *
	 * @return int Count
	 */
	private static function get_vulnerabilities_count() {
		$vulns = Bearmor_Vulnerability_Scanner::get_vulnerabilities();
		return count( $vulns );
	}

	/**
	 * Get firewall blocks count
	 *
	 * @param string $start_date Start date
	 * @return int Count
	 */
	private static function get_firewall_blocks_count( $start_date ) {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_firewall_blocks WHERE blocked_at >= %s",
				$start_date
			)
		);
	}

	/**
	 * Get login anomalies count
	 *
	 * @param string $start_date Start date
	 * @return int Count
	 */
	private static function get_login_anomalies_count( $start_date ) {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_anomalies WHERE detected_at >= %s",
				$start_date
			)
		);
	}

	/**
	 * Get latest AI analysis
	 *
	 * @return array|null Analysis data
	 */
	private static function get_latest_ai_analysis() {
		global $wpdb;

		return $wpdb->get_row(
			"SELECT * FROM {$wpdb->prefix}bearmor_ai_analyses ORDER BY created_at DESC LIMIT 1",
			ARRAY_A
		);
	}

	/**
	 * Download report file
	 *
	 * @param string $filename Filename
	 * @return void
	 */
	public static function download( $filename ) {
		$filepath = self::REPORT_DIR . $filename;

		error_log( 'BEARMOR PDF Download: Looking for ' . $filepath );
		error_log( 'BEARMOR PDF Download: File exists? ' . ( file_exists( $filepath ) ? 'YES' : 'NO' ) );
		error_log( 'BEARMOR PDF Download: Directory contents: ' . print_r( glob( self::REPORT_DIR . '*' ), true ) );

		if ( ! file_exists( $filepath ) ) {
			error_log( 'BEARMOR PDF Download: File not found - ' . $filepath );
			wp_die( 'File not found: ' . $filepath );
		}

		// Determine file type
		$is_html = strpos( $filename, '.html' ) !== false;

		if ( $is_html ) {
			header( 'Content-Type: text/html; charset=UTF-8' );
			header( 'Content-Disposition: inline; filename="' . basename( $filepath ) . '"' );
		} else {
			header( 'Content-Type: application/pdf' );
			header( 'Content-Disposition: attachment; filename="' . basename( $filepath ) . '"' );
		}

		header( 'Content-Length: ' . filesize( $filepath ) );
		readfile( $filepath );
		exit;
	}
}
