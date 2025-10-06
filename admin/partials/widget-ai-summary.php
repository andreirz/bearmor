<?php
/**
 * AI Summary Widget (Paid)
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if Pro is enabled (placeholder)
$is_pro = false;
?>

<div class="bearmor-ai-summary">
	<div class="bearmor-ai-header">
		<div class="bearmor-ai-title">
			<span class="dashicons dashicons-admin-generic"></span>
			<h3>AI Security Summary</h3>
		</div>
		<span class="bearmor-pro-badge">PRO</span>
	</div>
	<div class="bearmor-ai-content">
		<?php if ( $is_pro ) : ?>
			<div class="bearmor-ai-report">
				<p class="bearmor-ai-intro">📊 <strong>Last 7 Days Security Report</strong></p>
				<p class="bearmor-ai-text">
					Hello! I've analyzed your site's security over the past week. Here's what I found:
				</p>
				<p class="bearmor-ai-text">
					✅ <strong>Good news:</strong> No file changes detected, no malware found, and no suspicious login attempts. Your site is running smoothly!
				</p>
				<p class="bearmor-ai-text">
					💡 <strong>Recommendation:</strong> Consider enabling two-factor authentication for admin accounts and schedule weekly security scans to maintain this excellent security posture.
				</p>
				<p class="bearmor-ai-footer">
					<em>This AI-powered analysis helps you understand your security status in plain language.</em>
				</p>
			</div>
		<?php else : ?>
			<div class="bearmor-ai-upgrade">
				<p>🔒 Unlock AI-powered security insights</p>
				<p class="bearmor-widget-description">Get friendly, easy-to-understand security reports analyzing your last 7 days of activity, errors, and recommendations.</p>
				<a href="#" class="bearmor-upgrade-btn">Upgrade to Pro</a>
			</div>
		<?php endif; ?>
	</div>
</div>
