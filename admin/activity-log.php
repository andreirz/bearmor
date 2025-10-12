<?php
/**
 * Activity Log Admin Page
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get filter parameters
$action_filter = isset( $_GET['action_filter'] ) ? sanitize_text_field( $_GET['action_filter'] ) : '';
$user_filter = isset( $_GET['user_filter'] ) ? intval( $_GET['user_filter'] ) : 0;
$search = isset( $_GET['s'] ) ? sanitize_text_field( $_GET['s'] ) : '';

// Pagination
$per_page = 50;
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

// Enqueue CSS
wp_enqueue_style( 'bearmor-dashboard', plugins_url( 'assets/css/dashboard.css', dirname( __FILE__ ) ), array(), '1.0.0' );
?>

<div class="wrap">
	<div class="bearmor-header">
		<h1>📋 Activity Log</h1>
		<p class="bearmor-subtitle">Track admin actions and WordPress events</p>
	</div>

	<!-- Filters -->
	<div style="background: #fff; border: 1px solid #ccc; padding: 15px; margin: 20px 0; border-radius: 5px;">
		<form method="get" style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
			<input type="hidden" name="page" value="bearmor-activity-log">
			
			<select name="action_filter" style="min-width: 200px;">
				<option value="">All Actions</option>
				<?php foreach ( $actions as $action ) : ?>
					<option value="<?php echo esc_attr( $action ); ?>" <?php selected( $action_filter, $action ); ?>>
						<?php echo esc_html( Bearmor_Activity_Log::get_action_label( $action ) ); ?>
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
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width: 180px;">Date & Time</th>
					<th style="width: 120px;">User</th>
					<th style="width: 200px;">Action</th>
					<th>Details</th>
					<th style="width: 120px;">IP Address</th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $logs ) ) : ?>
					<tr>
						<td colspan="5" style="text-align: center; padding: 40px; color: #666;">
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
								<strong><?php echo esc_html( date( 'Y-m-d', strtotime( $log->created_at ) ) ); ?></strong><br>
								<small style="color: #666;"><?php echo esc_html( date( 'H:i:s', strtotime( $log->created_at ) ) ); ?></small>
							</td>
							<td>
								<strong><?php echo esc_html( $log->username ); ?></strong>
								<?php if ( $log->user_id === get_current_user_id() ) : ?>
									<br><small style="color: #666;">(you)</small>
								<?php endif; ?>
							</td>
							<td>
								<?php echo Bearmor_Activity_Log::get_action_label( $log->action ); ?>
							</td>
							<td>
								<?php if ( $log->object_type && $log->object_name ) : ?>
									<strong><?php echo esc_html( ucfirst( $log->object_type ) ); ?>:</strong>
									<code style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px;">
										<?php echo esc_html( $log->object_name ); ?>
									</code>
								<?php else : ?>
									<span style="color: #999;">—</span>
								<?php endif; ?>
							</td>
							<td>
								<code style="font-size: 11px;"><?php echo esc_html( $log->ip_address ); ?></code>
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

	<!-- Info Box -->
	<div style="background: #f0f6fc; border: 1px solid #c3e0f7; padding: 15px; margin: 20px 0; border-radius: 5px;">
		<h3 style="margin-top: 0;">ℹ️ About Activity Log</h3>
		<ul style="margin: 0; padding-left: 20px;">
			<li>Tracks logins, plugin/theme changes, user management, and Bearmor security actions</li>
			<li>Automatically keeps the last <strong><?php echo Bearmor_Activity_Log::MAX_RECORDS; ?></strong> records</li>
			<li>Records older than <strong>90 days</strong> are automatically deleted</li>
			<li>Lightweight and optimized for performance</li>
		</ul>
	</div>
</div>
