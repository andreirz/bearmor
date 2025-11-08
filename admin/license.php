<?php
/**
 * License Page
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$license_info = Bearmor_License::get_info();
$plan = $license_info['plan'];

?>
<div class="wrap">
	<h1>License & Activation</h1>

	<div class="bearmor-license-container">
		<!-- License Status Card -->
		<div class="license-card">
			<h2>Your Plan</h2>

			<div style="padding: 15px; background: #f9f9f9; margin: 15px 0; border-left: 4px solid #0073aa; display: flex; justify-content: space-between; align-items: center;">
				<p style="font-size: 18px; margin: 0;"><strong><?php echo esc_html( ucfirst( $plan ) ); ?> Plan</strong></p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings&action=refresh_license' ) ); ?>" class="button button-secondary">Refresh</a>
			</div>
		</div>

		<!-- Site Information -->
		<div class="license-card">
			<h2>Site Information</h2>

			<table class="form-table">
				<tr>
					<th scope="row">Site ID</th>
					<td>
						<?php if ( $license_info['site_id'] ) : ?>
							<code style="background: #f0f0f0; padding: 4px 8px; border-radius: 3px;"><?php echo esc_html( $license_info['site_id'] ); ?></code>
							<p class="description">Use this ID when contacting support</p>
							<em>Not generated yet</em>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row">Site URL</th>
					<td><?php echo esc_html( home_url() ); ?></td>
				</tr>
				<tr>
					<th scope="row">Site Name</th>
					<td><?php echo esc_html( get_bloginfo( 'name' ) ); ?></td>
				</tr>
			</table>
		</div>

		<!-- Help & Support -->
		<div class="license-card">
			<h2>Help & Support</h2>
			<ul style="list-style: disc; margin-left: 20px;">
				<li><a href="https://bearmor.com/docs/license" target="_blank">License Documentation</a></li>
				<li><a href="https://bearmor.com/docs/troubleshooting" target="_blank">Troubleshooting Guide</a></li>
				<li><a href="https://bearmor.com/support" target="_blank">Contact Support</a></li>
			</ul>
		</div>
	</div>
</div>

<style>
	.bearmor-license-container {
		max-width: 800px;
		margin: 20px 0;
	}

	.license-card {
		background: #fff;
		border: 1px solid #ccc;
		border-radius: 4px;
		padding: 20px;
		margin-bottom: 20px;
		box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
	}

	.license-card h2 {
		margin-top: 0;
		margin-bottom: 15px;
		font-size: 18px;
		border-bottom: 1px solid #eee;
		padding-bottom: 10px;
	}

	.license-card table {
		width: 100%;
	}

	.license-card table th {
		text-align: left;
		font-weight: bold;
		padding: 10px 0;
		border-bottom: 1px solid #eee;
	}

	.license-card table td {
		padding: 10px 0;
	}

	.license-card ul {
		margin: 0;
	}

	.license-card li {
		margin-bottom: 8px;
	}

	.license-card a {
		color: #0073aa;
		text-decoration: none;
	}

	.license-card a:hover {
		text-decoration: underline;
	}
</style>
