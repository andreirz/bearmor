<?php
/**
 * Scan Exclusions Settings
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="bearmor-settings-section">
	<h3>Scan Exclusions</h3>
	<p class="description">Exclude files and folders from security scans. One pattern per line.</p>

	<form method="post" action="options.php">
		<?php settings_fields( 'bearmor_scan_exclusions' ); ?>

		<table class="form-table">
			<tr>
				<th scope="row">
					<label for="bearmor_scan_exclusions">Exclusion Patterns</label>
				</th>
				<td>
					<textarea 
						id="bearmor_scan_exclusions" 
						name="bearmor_scan_exclusions" 
						rows="8" 
						cols="50"
						class="large-text code"
						placeholder="node_modules/&#10;vendor/&#10;*.min.js&#10;wp-content/cache/"
					><?php echo esc_textarea( Bearmor_Exclusions::get_patterns_text() ); ?></textarea>
					<p class="description">
						<strong>Examples:</strong><br>
						<code>node_modules/</code> - Exclude directory<br>
						<code>*.min.js</code> - Exclude file pattern<br>
						<code>wp-backup-*</code> - Exclude with wildcard<br>
						<code>.git/</code> - Exclude .git folder
					</p>
				</td>
			</tr>
		</table>

		<?php submit_button( 'Save Exclusions' ); ?>
	</form>

	<hr>

	<h4>Scheduled Scans</h4>
	<p class="description">Configure automatic security scans.</p>

	<form method="post" action="options.php">
		<?php settings_fields( 'bearmor_scheduled_scans' ); ?>

		<table class="form-table">
			<tr>
				<th scope="row">
					<label for="bearmor_malware_scan_enabled">Daily Malware Scan</label>
				</th>
				<td>
					<label>
						<input 
							type="checkbox" 
							id="bearmor_malware_scan_enabled" 
							name="bearmor_malware_scan_enabled" 
							value="1"
							<?php checked( get_option( 'bearmor_malware_scan_enabled', true ), 1 ); ?>
						>
						Enable daily malware scan at 2:00 AM
					</label>
					<?php
					$next_malware = Bearmor_Scan_Scheduler::get_next_scan_time( 'malware' );
					if ( $next_malware ) {
						echo '<p class="description">Next scan: ' . esc_html( wp_date( 'Y-m-d H:i:s', $next_malware ) ) . '</p>';
					}
					?>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label for="bearmor_deep_scan_enabled">Weekly Deep Scan</label>
				</th>
				<td>
					<label>
						<input 
							type="checkbox" 
							id="bearmor_deep_scan_enabled" 
							name="bearmor_deep_scan_enabled" 
							value="1"
							<?php checked( get_option( 'bearmor_deep_scan_enabled', false ), 1 ); ?>
						>
						Enable weekly deep scan on Sunday at 3:00 AM
					</label>
					<?php
					$next_deep = Bearmor_Scan_Scheduler::get_next_scan_time( 'deep' );
					if ( $next_deep ) {
						echo '<p class="description">Next scan: ' . esc_html( wp_date( 'Y-m-d H:i:s', $next_deep ) ) . '</p>';
					}
					?>
				</td>
			</tr>
		</table>

		<?php submit_button( 'Save Scan Schedule' ); ?>
	</form>
</div>
