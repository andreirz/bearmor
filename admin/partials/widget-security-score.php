<?php
/**
 * Security Score Widget
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if Pro
$is_pro = Bearmor_License::is_pro();

if ( $is_pro ) {
	// PRO: Calculate fixed 0-60 + get discretionary from AI
	$fixed_score = 0;
	
	// Fixed points (0-60)
	$threats = Bearmor_Malware_Scanner::get_threats( 'pending' );
	if ( empty( $threats ) ) {
		$fixed_score += 25; // No malware
	}
	
	if ( get_option( 'bearmor_header_x_frame' ) ) {
		$fixed_score += 10; // Hardening
	}
	
	if ( get_option( 'bearmor_2fa_enabled' ) ) {
		$fixed_score += 5; // 2FA
	}
	
	if ( is_ssl() ) {
		$fixed_score += 5; // SSL
	}
	
	$fixed_score += 10; // Firewall (Pro feature)
	
	// TODO: Add uptime check when available
	
	// Get discretionary score from AI
	$analysis = Bearmor_AI_Analyzer::get_latest_analysis();
	$discretionary_score = 0;
	$score_reason = '';
	
	if ( $analysis && isset( $analysis['discretionary_score'] ) ) {
		$discretionary_score = $analysis['discretionary_score'];
		$score_reason = isset( $analysis['score_reason'] ) ? $analysis['score_reason'] : '';
		$is_ai_score = true;
	} else {
		$is_ai_score = false;
	}
	
	// Total: fixed + discretionary, capped at 100
	$total_score = $fixed_score + $discretionary_score;
	$security_score = min( $total_score, 100 );
} else {
	// FREE: Use formula
	$score_data = Bearmor_Security_Score::calculate_free_score();
	$security_score = $score_data['score'];
	$is_ai_score = false;
}

// Get grade and color
$grade_data = Bearmor_Security_Score::get_grade_and_color( $security_score );
$grade = $grade_data['grade'];
$color = $grade_data['color'];
$label = $grade_data['label'];

// Map color to CSS class
$color_class_map = array(
	'green'  => 'good',
	'yellow' => 'warning',
	'orange' => 'warning',
	'red'    => 'critical',
);
$score_class = isset( $color_class_map[ $color ] ) ? $color_class_map[ $color ] : 'warning';
?>

<div class="bearmor-score-card">
	<div class="bearmor-score-circle <?php echo esc_attr( $score_class ); ?>">
		<div class="bearmor-score-number"><?php echo esc_html( $security_score ); ?></div>
		<div class="bearmor-score-label">
			<?php if ( $is_ai_score ) : ?>
				AI Score
			<?php else : ?>
				Security Score
			<?php endif; ?>
		</div>
	</div>
	<div class="bearmor-score-info">
		<p>Your site security is <?php echo $security_score >= 45 ? 'in good shape' : 'needs improvement'; ?>.</p>
		<h3><?php echo esc_html( $label ); ?> (<?php echo esc_html( $grade ); ?>)</h3>
		<?php if ( $is_pro && $is_ai_score ) : ?>
			<p style="font-size: 12px; margin-top: 8px; opacity: 0.85; line-height: 1.4;">
				<strong>Fixed:</strong> <?php echo esc_html( $fixed_score ); ?>/60 | 
				<strong>AI:</strong> <?php echo esc_html( $discretionary_score ); ?>/50
				<?php if ( $score_reason ) : ?>
					<br><em><?php echo esc_html( $score_reason ); ?></em>
				<?php endif; ?>
			</p>
		<?php endif; ?>
	</div>
</div>
