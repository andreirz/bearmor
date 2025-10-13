<?php
/**
 * Security Logs Admin Page
 * Combined Activity Log + Firewall Blocks
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// === ACTIVITY LOG ===
// Get filter parameters
$action_filter = isset( $_GET['action_filter'] ) ? sanitize_text_field( $_GET['action_filter'] ) : '';
$user_filter = isset( $_GET['user_filter'] ) ? intval( $_GET['user_filter'] ) : 0;
$search = isset( $_GET['s'] ) ? sanitize_text_field( $_GET['s'] ) : '';

// Pagination
$per_page = 25; // Reduced to fit side-by-side
$current_page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
$offset = ( $current_page - 1 ) * $per_page;

// Build query args
$args = array(
	'limit'  => $per_page,
	'offset' => $offset,
);

if ( $action_filter ) {
	$args['action'] = $action_filter;
}

if ( $user_filter ) {
	$args['user_id'] = $user_filter;
}

if ( $search ) {
	$args['search'] = $search;
}

// Get logs
$logs = Bearmor_Activity_Log::get_logs( $args );
$total_items = Bearmor_Activity_Log::get_count( $args );
$total_pages = ceil( $total_items / $per_page );

// Get unique actions for filter
global $wpdb;
$actions = $wpdb->get_col( "SELECT DISTINCT action FROM {$wpdb->prefix}bearmor_activity_log ORDER BY action" );

// Get users for filter
$users = get_users( array( 'fields' => array( 'ID', 'user_login' ) ) );

// === FIREWALL BLOCKS ===
$firewall_per_page = 25;
$firewall_page = isset( $_GET['firewall_paged'] ) ? max( 1, intval( $_GET['firewall_paged'] ) ) : 1;
$firewall_offset = ( $firewall_page - 1 ) * $firewall_per_page;

$firewall_blocks = $wpdb->get_results(
	$wpdb->prepare(
		"SELECT * FROM {$wpdb->prefix}bearmor_firewall_blocks 
		ORDER BY blocked_at DESC 
		LIMIT %d OFFSET %d",
		$firewall_per_page,
		$firewall_offset
	)
);

$firewall_total = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_firewall_blocks" );
$firewall_total_pages = ceil( $firewall_total / $firewall_per_page );

// Enqueue CSS
wp_enqueue_style( 'bearmor-dashboard', plugins_url( 'assets/css/dashboard.css', dirname( __FILE__ ) ), array(), '1.0.0' );
?>

<div class="wrap">
	<div class="bearmor-header">
		<h1>📋 Security Logs</h1>
		<p class="bearmor-subtitle">Activity log and firewall blocks</p>
	</div>

	<!-- Two Column Layout -->
	<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
		
		<!-- LEFT: Activity Log -->
		<div>
			<h2 style="margin: 0 0 15px 0;">👤 Activity Log</h2>
			
			<!-- Filters -->
			<div style="background: #fff; border: 1px solid #ccc; padding: 10px; margin-bottom: 15px; border-radius: 5px;">
				<form method="get" style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
					<input type="hidden" name="page" value="bearmor-activity-log">
					
					<select name="action_filter" style="min-width: 150px; font-size: 12px;">
						<option value="">All Actions</option>
						<?php foreach ( $actions as $action ) : ?>
					<option value="<?php echo esc_attr( $action ); ?>" <?php selected( $action_filter, $action ); ?>>
						<?php echo esc_html( wp_strip_all_tags( Bearmor_Activity_Log::get_action_label( $action ) ) ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			
			<select name="user_filter" style="min-width: 150px;">
				<option value="">All Users</option>
				<?php foreach ( $users as $user ) : ?>
					<option value="<?php echo esc_attr( $user->ID ); ?>" <?php selected( $user_filter, $user->ID ); ?>>
						<?php echo esc_html( $user->user_login ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			
			<input type="search" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="Search..." style="min-width: 200px;">
			
			<button type="submit" class="button">Filter</button>
			
			<?php if ( $action_filter || $user_filter || $search ) : ?>
				<a href="<?php echo admin_url( 'admin.php?page=bearmor-activity-log' ); ?>" class="button">Clear Filters</a>
			<?php endif; ?>
			
			<div style="margin-left: auto; color: #666; font-size: 13px;">
				Total: <?php echo number_format( $total_items ); ?> records
				<?php
				$total_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_activity_log" );
				if ( $total_count >= Bearmor_Activity_Log::MAX_RECORDS ) {
					echo ' <span style="color: #d63638;">(Limit: ' . Bearmor_Activity_Log::MAX_RECORDS . ')</span>';
				}
				?>
			</div>
		</form>
	</div>

	<!-- Activity Log Table -->
	<div style="background: #fff; border: 1px solid #ccc; border-radius: 5px; overflow: hidden;">
		<table class="wp-list-table widefat fixed striped" style="font-size: 12px;">
			<thead>
				<tr>
					<th style="width: 110px;">User</th>
					<th>Action</th>
					<th>Details</th>
					<th style="width: 90px;">IP</th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $logs ) ) : ?>
					<tr>
						<td colspan="4" style="text-align: center; padding: 40px; color: #666;">
							📋 No activity logs found
							<?php if ( $action_filter || $user_filter || $search ) : ?>
								<br><small>Try adjusting your filters</small>
							<?php endif; ?>
						</td>
					</tr>
				<?php else : ?>
					<?php foreach ( $logs as $log ) : ?>
						<?php $is_critical = ( $log->action === 'plugin_auto_disabled' ); ?>
						<tr<?php echo $is_critical ? ' style="background: #fff5f5; border-left: 3px solid #d63638;"' : ''; ?>>
							<td>
								<strong><?php echo esc_html( $log->username ); ?></strong><br>
								<small style="color: #666;"><?php echo esc_html( date( 'd.m.Y H:i', strtotime( $log->created_at ) ) ); ?></small>
							</td>
							<td>
								<?php echo Bearmor_Activity_Log::get_action_label( $log->action ); ?>
							</td>
							<td>
								<?php if ( $log->object_type && $log->object_name ) : ?>
									<strong><?php echo esc_html( ucfirst( $log->object_type ) ); ?>:</strong>
									<code style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 11px;">
										<?php echo esc_html( $log->object_name ); ?>
									</code>
								<?php else : ?>
									<span style="color: #999;">—</span>
								<?php endif; ?>
							</td>
							<td>
								<code style="font-size: 10px;"><?php echo esc_html( $log->ip_address ); ?></code>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>
	</div>

	<!-- Pagination -->
	<?php if ( $total_pages > 1 ) : ?>
		<div style="margin: 20px 0; text-align: center;">
			<?php
			$base_url = add_query_arg( array(
				'page'          => 'bearmor-activity-log',
				'action_filter' => $action_filter,
				'user_filter'   => $user_filter,
				's'             => $search,
			), admin_url( 'admin.php' ) );
			
			echo paginate_links( array(
				'base'      => add_query_arg( 'paged', '%#%', $base_url ),
				'format'    => '',
				'current'   => $current_page,
				'total'     => $total_pages,
				'prev_text' => '« Previous',
				'next_text' => 'Next »',
			) );
			?>
		</div>
	<?php endif; ?>

		</div><!-- End Activity Log Column -->
		
		<!-- RIGHT: Firewall Blocks -->
		<div>
			<h2 style="margin: 0 0 15px 0;">🔥 Firewall Blocks</h2>
			
			<!-- Firewall Stats -->
			<div style="background: #fff; border: 1px solid #ccc; padding: 10px; margin-bottom: 15px; border-radius: 5px;">
				<div style="display: flex; justify-content: space-between; font-size: 12px;">
					<span><strong>Total Blocks:</strong> <?php echo number_format( $firewall_total ); ?></span>
					<span><strong>Last 24h:</strong> <?php
						$last_24h = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_firewall_blocks WHERE blocked_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)" );
						echo number_format( $last_24h );
					?></span>
				</div>
			</div>
			
			<!-- Firewall Table -->
			<div style="background: #fff; border: 1px solid #ccc; border-radius: 5px; overflow: hidden;">
				<table class="wp-list-table widefat fixed striped" style="font-size: 12px;">
					<thead>
						<tr>
							<th style="width: 100px;">Time</th>
							<th style="width: 100px;">IP Address</th>
							<th>Attack Type</th>
							<th>Request URI</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $firewall_blocks ) ) : ?>
							<tr>
								<td colspan="4" style="text-align: center; padding: 40px; color: #666;">
									🔥 No firewall blocks yet
								</td>
							</tr>
						<?php else : ?>
							<?php foreach ( $firewall_blocks as $block ) : ?>
								<tr>
									<td>
										<strong><?php echo esc_html( date( 'M d', strtotime( $block->blocked_at ) ) ); ?></strong><br>
										<small style="color: #666;"><?php echo esc_html( date( 'H:i', strtotime( $block->blocked_at ) ) ); ?></small>
									</td>
									<td>
										<code style="font-size: 10px;"><?php echo esc_html( $block->ip_address ); ?></code>
									</td>
									<td>
										<span style="background: #d63638; color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">
											<?php echo esc_html( $block->rule_matched ); ?>
										</span>
									</td>
									<td>
										<small style="color: #666; font-size: 10px;" title="<?php echo esc_attr( $block->request_uri ); ?>">
											<?php echo esc_html( substr( $block->request_uri, 0, 40 ) ); ?><?php echo strlen( $block->request_uri ) > 40 ? '...' : ''; ?>
										</small>
									</td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
			
			<!-- Firewall Pagination -->
			<?php if ( $firewall_total_pages > 1 ) : ?>
				<div style="margin: 15px 0; text-align: center; font-size: 12px;">
					<?php
					$firewall_base_url = add_query_arg( array(
						'page' => 'bearmor-activity-log',
					), admin_url( 'admin.php' ) );
					
					echo paginate_links( array(
						'base'      => add_query_arg( 'firewall_paged', '%#%', $firewall_base_url ),
						'format'    => '',
						'current'   => $firewall_page,
						'total'     => $firewall_total_pages,
						'prev_text' => '«',
						'next_text' => '»',
					) );
					?>
				</div>
			<?php endif; ?>
		</div><!-- End Firewall Column -->
		
	</div><!-- End Two Column Grid -->

</div>
