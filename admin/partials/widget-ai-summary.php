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

// Check if Pro feature is available
$is_pro = Bearmor_License::is_pro();

// Get latest AI analysis
$analysis = $is_pro ? Bearmor_AI_Analyzer::get_latest_analysis() : null;

// Debug: Check if table exists and has data
global $wpdb;
$table_name = $wpdb->prefix . 'bearmor_ai_analyses';
$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" );
$row_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
error_log( "BEARMOR AI Widget Debug: Table exists: " . ( $table_exists ? 'YES' : 'NO' ) . ", Rows: " . $row_count );
if ( $analysis ) {
	error_log( "BEARMOR AI Widget: Latest analysis ID: " . $analysis['id'] . ", Created: " . $analysis['created_at'] );
}

// Calculate score for color class
$score_class = 'neutral';
if ( $analysis ) {
	// Calculate fixed + discretionary score
	$fixed_score = 0;
	$threats = Bearmor_Malware_Scanner::get_threats( 'pending' );
	if ( empty( $threats ) ) {
		$fixed_score += 25;
	}
	if ( get_option( 'bearmor_header_x_frame' ) ) {
		$fixed_score += 10;
	}
	if ( get_option( 'bearmor_2fa_enabled' ) ) {
		$fixed_score += 5;
	}
	if ( is_ssl() ) {
		$fixed_score += 5;
	}
	$fixed_score += 10; // Firewall
	
	$discretionary_score = isset( $analysis['discretionary_score'] ) ? $analysis['discretionary_score'] : 0;
	$total_score = min( $fixed_score + $discretionary_score, 100 );
	
	// Map score to class
	if ( $total_score >= 80 ) {
		$score_class = 'excellent';
	} elseif ( $total_score >= 60 ) {
		$score_class = 'good';
	} elseif ( $total_score >= 40 ) {
		$score_class = 'warning';
	} else {
		$score_class = 'critical';
	}
}

$color_rating = $analysis ? $analysis['color_rating'] : 'gray';
?>

<div class="bearmor-ai-summary bearmor-ai-summary-<?php echo esc_attr( $score_class ); ?>">
	<div class="bearmor-ai-header">
		<div class="bearmor-ai-title">
			<span class="dashicons dashicons-shield-alt"></span>
			<h3>AI Security Summary</h3>
		</div>
	</div>
	<div class="bearmor-ai-content">
		<?php if ( ! $is_pro ) : ?>
			<!-- Pro Feature Overlay -->
			<div style="
				background: #f5f5f5;
				border: 2px solid #ddd;
				border-radius: 8px;
				padding: 30px;
				text-align: center;
			">
				<h3 style="color: #666; margin-top: 0;">🔒 Pro Feature</h3>
				<p style="color: #999; font-size: 14px; margin: 10px 0;">
					AI Security Summary is available for Pro members only.
				</p>
				<p style="color: #999; margin: 20px 0;">
					Get AI-powered analysis of your security data with actionable insights and recommendations.
				</p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="button button-primary" style="background: #8269FF; border-color: #8269FF;">
					Upgrade to Pro
				</a>
			</div>
		<?php elseif ( $analysis ) : ?>
		<!-- AI Response with color-based class -->
		<div class="bearmor-ai-report bearmor-ai-report-<?php echo esc_attr( $color_rating ); ?>" style="padding: 15px; border-radius: 8px; margin-bottom: 15px;">
			<p class="bearmor-ai-meta" style="margin: 0 0 12px 0; font-size: 12px; color: #666;">
Analysis from <?php echo esc_html( $analysis['model_used'] ); ?> (<?php echo number_format( $analysis['tokens_used'] ); ?> tokens) - <?php echo human_time_diff( strtotime( $analysis['created_at'] ), current_time( 'timestamp' ) ); ?> ago
			</p>
			<div class="bearmor-ai-response" style="line-height: 1.6; font-size: 14px; white-space: pre-wrap;">
<?php 
	// Convert markdown to HTML
	$response = $analysis['ai_response'];
	// Bold: **text** -> <strong>text</strong>
	$response = preg_replace( '/\*\*(.+?)\*\*/', '<strong>$1</strong>', $response );
	// Italic: *text* -> <em>text</em>
	$response = preg_replace( '/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/', '<em>$1</em>', $response );
	echo wp_kses_post( $response );
?>
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
					<pre style="margin: 0 0 15px 0; padding: 10px; background: #f9f9f9; border: 1px solid #eee; border-radius: 3px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;">You are a friendly, helpful WordPress security advisor. Your job is to help shop owners understand their site security in simple, non-technical language. Be reassuring and positive. Remember: firewall blocks, failed logins, and login anomalies are GOOD - they mean the plugin is protecting the site. ALWAYS include [SCORE: XX] in your response.</pre>

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
