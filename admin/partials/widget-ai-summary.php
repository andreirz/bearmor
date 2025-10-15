<?php
/**
 * AI Summary Widget
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get latest AI analysis
$analysis = Bearmor_AI_Analyzer::get_latest_analysis();

// Debug: Check if table exists and has data
global $wpdb;
$table_name = $wpdb->prefix . 'bearmor_ai_analyses';
$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" );
$row_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
error_log( "BEARMOR AI Widget Debug: Table exists: " . ( $table_exists ? 'YES' : 'NO' ) . ", Rows: " . $row_count );
if ( $analysis ) {
	error_log( "BEARMOR AI Widget: Latest analysis ID: " . $analysis['id'] . ", Created: " . $analysis['created_at'] );
}

$color_rating = $analysis ? $analysis['color_rating'] : 'gray';
?>

<div class="bearmor-ai-summary">
	<div class="bearmor-ai-header">
		<div class="bearmor-ai-title">
			<span class="dashicons dashicons-shield-alt"></span>
			<h3>AI Security Summary</h3>
		</div>
	</div>
	<div class="bearmor-ai-content">
		<?php if ( $analysis ) : ?>
		<!-- AI Response with color-based class -->
		<div class="bearmor-ai-report bearmor-ai-report-<?php echo esc_attr( $color_rating ); ?>" style="padding: 15px; border-radius: 8px; margin-bottom: 15px;">
			<p class="bearmor-ai-meta" style="margin: 0 0 12px 0; font-size: 12px; color: #666;">
Analysis from <?php echo esc_html( $analysis['model_used'] ); ?> (<?php echo number_format( $analysis['tokens_used'] ); ?> tokens) - <?php echo human_time_diff( strtotime( $analysis['created_at'] ), current_time( 'timestamp' ) ); ?> ago
			</p>
			<div class="bearmor-ai-response" style="line-height: 1.6; font-size: 14px; white-space: pre-wrap;">
<?php echo esc_html( $analysis['ai_response'] ); ?>
			</div>
		</div>

			<!-- Refresh button -->
			<p style="margin: 10px 0; text-align: center;">
				<button class="button button-primary" onclick="bearmor_trigger_ai_analysis(); return false;">
					Refresh Analysis
				</button>
			</p>

			<!-- Debug: Show prompt sent to AI -->
			<details style="margin-top: 15px; padding: 10px; background: #f5f5f5; border-radius: 5px; border: 1px solid #ddd;">
				<summary style="cursor: pointer; font-weight: bold; color: #333; padding: 5px;">
					Debug: Full Prompt Sent to OpenAI
				</summary>
				<div style="margin-top: 10px;">
					<p style="margin: 0 0 10px 0; font-size: 11px; color: #666; font-weight: bold;">
						SYSTEM MESSAGE (AI Behavior):
					</p>
					<pre style="margin: 0 0 15px 0; padding: 10px; background: #f9f9f9; border: 1px solid #eee; border-radius: 3px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;">You are a friendly, helpful WordPress security advisor. Your job is to help shop owners understand their site security in simple, non-technical language. Be reassuring and positive. You MUST start every response with [COLOR-RATING: X] where X is GREEN, GRAY, YELLOW, or RED. Remember: firewall blocks, failed logins, and login anomalies are GOOD - they mean the plugin is protecting the site.</pre>

					<p style="margin: 0 0 10px 0; font-size: 11px; color: #666; font-weight: bold;">
						USER PROMPT + SECURITY DATA (combined):
					</p>
					<pre style="margin: 0; padding: 10px; background: #f9f9f9; border: 1px solid #eee; border-radius: 3px; font-size: 11px; overflow-x: auto; max-height: 500px; overflow-y: auto; white-space: pre-wrap;">
<?php echo esc_html( $analysis['ai_prompt'] ); ?>
					</pre>
				</div>
			</details>

		<?php else : ?>
			<div class="bearmor-ai-report" style="padding: 20px; text-align: center; background: #f9f9f9; border-radius: 8px;">
				<p style="font-size: 14px; color: #666; margin: 0;">
					No AI analysis yet. Click below to run the first analysis.
				</p>
				<p style="margin: 15px 0 0 0;">
					<button class="button button-primary" onclick="bearmor_trigger_ai_analysis(); return false;">
						Run AI Analysis Now
					</button>
				</p>
			</div>
		<?php endif; ?>
	</div>
</div>

<script>
function bearmor_trigger_ai_analysis() {
	if ( !confirm( 'Run AI analysis now? This will analyze your last 7 days of security data.' ) ) {
		return;
	}
	
	var button = event.target;
	button.disabled = true;
	button.textContent = 'Running...';
	
	jQuery.post( ajaxurl, {
		action: 'bearmor_trigger_ai_analysis',
		nonce: '<?php echo wp_create_nonce( 'bearmor_ai_analysis' ); ?>'
	}, function( response ) {
		console.log( 'AI Analysis Response:', response );
		if ( response.success ) {
			console.log( 'Analysis successful, reloading page...' );
			setTimeout( function() {
				location.reload();
			}, 500 );
		} else {
			alert( 'Error: ' + ( response.data ? response.data.message : 'Unknown error' ) );
			button.disabled = false;
			button.textContent = 'Refresh Analysis';
		}
	}).fail( function( xhr, status, error ) {
		console.error( 'AJAX Error:', error, xhr.responseText );
		alert( 'Network error: ' + error );
		button.disabled = false;
		button.textContent = 'Refresh Analysis';
	});
}
</script>
