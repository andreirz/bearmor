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

// Calculate security score (placeholder logic)
$security_score = 85;
$score_class = $security_score >= 80 ? 'good' : ( $security_score >= 60 ? 'warning' : 'critical' );
$score_text = $security_score >= 80 ? 'Excellent' : ( $security_score >= 60 ? 'Needs Attention' : 'Critical' );
?>

<div class="bearmor-score-card">
	<div class="bearmor-score-circle <?php echo esc_attr( $score_class ); ?>">
		<div class="bearmor-score-number"><?php echo esc_html( $security_score ); ?></div>
		<div class="bearmor-score-label">Security Score</div>
	</div>
	<div class="bearmor-score-info">
		<h3><?php echo esc_html( $score_text ); ?></h3>
		<p>Your site security is <?php echo $security_score >= 80 ? 'in good shape' : 'needs improvement'; ?>.</p>
	</div>
</div>
