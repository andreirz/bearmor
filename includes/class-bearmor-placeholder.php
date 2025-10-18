<?php
/**
 * Placeholder Content Generator - Demo data for Pro features
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Placeholder {

	/**
	 * Get placeholder firewall blocks (grayed out, demo data)
	 *
	 * @return array Placeholder blocks
	 */
	public static function get_firewall_blocks() {
		return array(
			array(
				'blocked_at'  => date( 'Y-m-d H:i:s', strtotime( '-2 hours' ) ),
				'ip_address'  => '203.0.113.45',
				'rule_matched' => 'SQL Injection',
				'request_uri' => '/wp-admin/admin-ajax.php?action=get_posts&id=1 OR 1=1',
			),
			array(
				'blocked_at'  => date( 'Y-m-d H:i:s', strtotime( '-4 hours' ) ),
				'ip_address'  => '198.51.100.89',
				'rule_matched' => 'XSS Attack',
				'request_uri' => '/search?q=<script>alert("xss")</script>',
			),
			array(
				'blocked_at'  => date( 'Y-m-d H:i:s', strtotime( '-6 hours' ) ),
				'ip_address'  => '192.0.2.123',
				'rule_matched' => 'Path Traversal',
				'request_uri' => '/wp-content/../../wp-config.php',
			),
			array(
				'blocked_at'  => date( 'Y-m-d H:i:s', strtotime( '-8 hours' ) ),
				'ip_address'  => '203.0.113.78',
				'rule_matched' => 'Malicious Bot',
				'request_uri' => '/wp-login.php?user=admin&pass=123456',
			),
		);
	}

	/**
	 * Get placeholder vulnerabilities (grayed out, demo data)
	 *
	 * @return array Placeholder vulnerabilities
	 */
	public static function get_vulnerabilities() {
		return array(
			array(
				'item_name'    => 'WooCommerce',
				'item_type'    => 'plugin',
				'item_slug'    => 'woocommerce',
				'severity'     => 'high',
				'title'        => 'Unauthenticated SQL Injection',
				'description'  => 'A SQL injection vulnerability was discovered in WooCommerce versions before 7.2.0.',
				'fixed_in'     => '7.2.0',
				'cve_references' => 'CVE-2023-12345',
			),
			array(
				'item_name'    => 'Elementor',
				'item_type'    => 'plugin',
				'item_slug'    => 'elementor',
				'severity'     => 'medium',
				'title'        => 'Stored XSS in Page Builder',
				'description'  => 'A stored XSS vulnerability allows authenticated users to inject malicious scripts.',
				'fixed_in'     => '3.15.0',
				'cve_references' => 'CVE-2023-54321',
			),
			array(
				'item_name'    => 'Astra Theme',
				'item_type'    => 'theme',
				'item_slug'    => 'astra',
				'severity'     => 'low',
				'title'        => 'Outdated jQuery Version',
				'description'  => 'The theme uses an outdated version of jQuery with known vulnerabilities.',
				'fixed_in'     => '4.2.0',
				'cve_references' => '',
			),
		);
	}

	/**
	 * Get placeholder deep scan results (grayed out, demo data)
	 *
	 * @return array Placeholder scan results
	 */
	public static function get_deep_scan_results() {
		return array(
			array(
				'scan_type'    => 'database',
				'detected_at'  => date( 'Y-m-d H:i:s', strtotime( '-1 day' ) ),
				'location'     => 'wp_posts.post_content (ID: 42)',
				'threat_type'  => 'Malicious Script',
				'snippet'      => '<iframe src="http://malicious-site.com/inject.js"></iframe>',
				'severity'     => 'critical',
			),
			array(
				'scan_type'    => 'uploads',
				'detected_at'  => date( 'Y-m-d H:i:s', strtotime( '-2 days' ) ),
				'location'     => '/wp-content/uploads/2024/01/shell.php',
				'threat_type'  => 'Web Shell',
				'snippet'      => '<?php system($_GET["cmd"]); ?>',
				'severity'     => 'critical',
			),
			array(
				'scan_type'    => 'database',
				'detected_at'  => date( 'Y-m-d H:i:s', strtotime( '-3 days' ) ),
				'location'     => 'wp_options.option_value',
				'threat_type'  => 'Backdoor Code',
				'snippet'      => 'eval(base64_decode($_POST["x"]));',
				'severity'     => 'high',
			),
		);
	}

	/**
	 * Render placeholder content with grayed-out styling
	 *
	 * @param string $type Type of placeholder (firewall, vulnerabilities, deep_scan)
	 */
	public static function render_placeholder( $type = 'firewall' ) {
		$opacity = 'opacity: 0.5; filter: grayscale(100%);';
		
		switch ( $type ) {
			case 'firewall':
				self::render_firewall_placeholder( $opacity );
				break;
			case 'vulnerabilities':
				self::render_vulnerabilities_placeholder( $opacity );
				break;
			case 'deep_scan':
				self::render_deep_scan_placeholder( $opacity );
				break;
		}
	}

	/**
	 * Render firewall placeholder
	 *
	 * @param string $opacity CSS opacity style
	 */
	private static function render_firewall_placeholder( $opacity ) {
		$blocks = self::get_firewall_blocks();
		?>
		<div style="<?php echo esc_attr( $opacity ); ?>">
			<div style="background: #fff; border: 1px solid #ccc; padding: 10px; margin-bottom: 15px; border-radius: 5px;">
				<div style="display: flex; justify-content: space-between; font-size: 12px;">
					<span><strong>Total Blocks:</strong> 1,247</span>
					<span><strong>Last 24h:</strong> 89</span>
				</div>
			</div>
			
			<div style="background: #fff; border: 1px solid #ccc; border-radius: 5px; overflow: hidden;">
				<table class="wp-list-table widefat fixed striped" style="font-size: 12px;">
					<thead>
						<tr>
							<th style="width: 100px;">Time</th>
							<th style="width: 100px;">IP Address</th>
							<th>Rule Matched</th>
							<th>Request URI</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $blocks as $block ) : ?>
							<tr>
								<td>
									<strong><?php echo esc_html( date( 'M d', strtotime( $block['blocked_at'] ) ) ); ?></strong><br>
									<small style="color: #666;"><?php echo esc_html( date( 'H:i', strtotime( $block['blocked_at'] ) ) ); ?></small>
								</td>
								<td>
									<code style="font-size: 10px;"><?php echo esc_html( $block['ip_address'] ); ?></code>
								</td>
								<td>
									<span style="background: #d63638; color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">
										<?php echo esc_html( $block['rule_matched'] ); ?>
									</span>
								</td>
								<td>
									<small style="color: #666; font-size: 10px;" title="<?php echo esc_attr( $block['request_uri'] ); ?>">
										<?php echo esc_html( substr( $block['request_uri'], 0, 40 ) ); ?><?php echo strlen( $block['request_uri'] ) > 40 ? '...' : ''; ?>
									</small>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p style="margin: 10px 0; font-size: 11px; color: #999; text-align: center;">
				<em>Demo data - This is example content showing what Pro features look like</em>
			</p>
		</div>
		<?php
	}

	/**
	 * Render vulnerabilities placeholder
	 *
	 * @param string $opacity CSS opacity style
	 */
	private static function render_vulnerabilities_placeholder( $opacity ) {
		$vulns = self::get_vulnerabilities();
		?>
		<div style="<?php echo esc_attr( $opacity ); ?>">
			<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0;">
				<div style="background: #fff; border-left: 4px solid #d63638; padding: 20px; border-radius: 5px;">
					<h3 style="margin: 0; font-size: 32px; color: #d63638;">2</h3>
					<p style="margin: 5px 0 0 0; color: #666;">Critical</p>
				</div>
				<div style="background: #fff; border-left: 4px solid #f56e28; padding: 20px; border-radius: 5px;">
					<h3 style="margin: 0; font-size: 32px; color: #f56e28;">1</h3>
					<p style="margin: 5px 0 0 0; color: #666;">High</p>
				</div>
				<div style="background: #fff; border-left: 4px solid #ffb81c; padding: 20px; border-radius: 5px;">
					<h3 style="margin: 0; font-size: 32px; color: #ffb81c;">1</h3>
					<p style="margin: 5px 0 0 0; color: #666;">Medium</p>
				</div>
			</div>

			<div style="background: #fff; border: 1px solid #ccc; border-radius: 5px; overflow: hidden;">
				<table class="wp-list-table widefat fixed striped" style="font-size: 12px;">
					<thead>
						<tr>
							<th>Plugin/Theme</th>
							<th style="width: 80px;">Severity</th>
							<th>Vulnerability</th>
							<th style="width: 100px;">Fixed In</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $vulns as $vuln ) : ?>
							<tr>
								<td>
									<strong><?php echo esc_html( $vuln['item_name'] ); ?></strong><br>
									<small style="color: #999;"><?php echo esc_html( ucfirst( $vuln['item_type'] ) ); ?></small>
								</td>
								<td>
									<?php
									$color = 'high' === $vuln['severity'] ? '#d63638' : ( 'medium' === $vuln['severity'] ? '#ffb81c' : '#2271b1' );
									?>
									<span style="background: <?php echo esc_attr( $color ); ?>; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">
										<?php echo esc_html( ucfirst( $vuln['severity'] ) ); ?>
									</span>
								</td>
								<td><?php echo esc_html( $vuln['title'] ); ?></td>
								<td><code style="background: #f5f5f5; padding: 2px 4px;">v<?php echo esc_html( $vuln['fixed_in'] ); ?></code></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p style="margin: 10px 0; font-size: 11px; color: #999; text-align: center;">
				<em>Demo data - This is example content showing what Pro features look like</em>
			</p>
		</div>
		<?php
	}

	/**
	 * Render deep scan placeholder
	 *
	 * @param string $opacity CSS opacity style
	 */
	private static function render_deep_scan_placeholder( $opacity ) {
		$results = self::get_deep_scan_results();
		?>
		<div style="<?php echo esc_attr( $opacity ); ?>">
			<div style="background: #fff; border: 1px solid #ccc; border-radius: 5px; overflow: hidden;">
				<table class="wp-list-table widefat fixed striped" style="font-size: 12px;">
					<thead>
						<tr>
							<th>Location</th>
							<th style="width: 100px;">Threat Type</th>
							<th style="width: 80px;">Severity</th>
							<th style="width: 100px;">Detected</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $results as $result ) : ?>
							<tr>
								<td>
									<strong><?php echo esc_html( $result['location'] ); ?></strong><br>
									<small style="color: #999;"><?php echo esc_html( $result['scan_type'] ); ?> scan</small>
								</td>
								<td><?php echo esc_html( $result['threat_type'] ); ?></td>
								<td>
									<?php
									$color = 'critical' === $result['severity'] ? '#d63638' : '#f56e28';
									?>
									<span style="background: <?php echo esc_attr( $color ); ?>; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">
										<?php echo esc_html( ucfirst( $result['severity'] ) ); ?>
									</span>
								</td>
								<td><small><?php echo esc_html( date( 'M d, H:i', strtotime( $result['detected_at'] ) ) ); ?></small></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p style="margin: 10px 0; font-size: 11px; color: #999; text-align: center;">
				<em>Demo data - This is example content showing what Pro features look like</em>
			</p>
		</div>
		<?php
	}
}
