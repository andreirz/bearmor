<?php
/**
 * Uptime Widget
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if Pro is enabled
$is_pro = class_exists( 'Bearmor_License' ) && Bearmor_License::is_pro();

// Get uptime stats
$uptime_stats = array(
	'uptime_percent'  => 0,
	'total_downtime'  => 0,
	'downtime_events' => array(),
);

if ( $is_pro && class_exists( 'Bearmor_Uptime_Sync' ) ) {
	$uptime_stats = Bearmor_Uptime_Sync::get_uptime_stats();
}

// Generate 7-day uptime data for chart (calculate per day from actual pings)
$chart_data = array();
$chart_labels = array();

global $wpdb;
for ( $i = 6; $i >= 0; $i-- ) {
	$date = date( 'M d', strtotime( "-$i days" ) );
	$day_start = date( 'Y-m-d 00:00:00', strtotime( "-$i days" ) );
	$day_end = date( 'Y-m-d 23:59:59', strtotime( "-$i days" ) );
	
	// Count pings for this day
	$total_pings = $wpdb->get_var( $wpdb->prepare(
		"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_uptime_pings 
		WHERE pinged_at >= %s AND pinged_at <= %s",
		$day_start,
		$day_end
	) );
	
	$up_pings = $wpdb->get_var( $wpdb->prepare(
		"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_uptime_pings 
		WHERE pinged_at >= %s AND pinged_at <= %s AND status = 'up'",
		$day_start,
		$day_end
	) );
	
	$day_uptime = $total_pings > 0 ? round( ( $up_pings / $total_pings ) * 100, 0 ) : 100;
	$chart_labels[] = $date;
	$chart_data[] = $day_uptime;
}

$status_class = $uptime_stats['uptime_percent'] >= 99 ? 'excellent' : 
                ( $uptime_stats['uptime_percent'] >= 95 ? 'good' : 
                ( $uptime_stats['uptime_percent'] >= 90 ? 'warning' : 'critical' ) );

// Get last downtime event (if within 7 days)
$last_downtime = null;
$seven_days_ago = strtotime( '-7 days' );
if ( ! empty( $uptime_stats['downtime_events'] ) ) {
	foreach ( $uptime_stats['downtime_events'] as $event ) {
		$event_start = strtotime( $event->start_time );
		if ( $event_start >= $seven_days_ago ) {
			$last_downtime = $event;
			break; // First one is the most recent
		}
	}
}
?>

<div class="bearmor-widget bearmor-widget-uptime bearmor-uptime-<?php echo esc_attr( $status_class ); ?> <?php echo ! $is_pro ? 'bearmor-widget-pro' : ''; ?>">
	<?php if ( ! $is_pro ) : ?>
		<div class="bearmor-pro-badge">PRO</div>
	<?php endif; ?>
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-clock"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Uptime Monitoring</h3>
		<?php if ( $is_pro ) : ?>
			<div class="bearmor-uptime-stats">
				<p class="bearmor-uptime-percentage bearmor-uptime-<?php echo esc_attr( $status_class ); ?>">
					<?php echo esc_html( $uptime_stats['uptime_percent'] ); ?>%
				</p>
			</div>
			
			<!-- Chart -->
			<div class="bearmor-uptime-chart" id="bearmor-uptime-chart" style="margin-top: 8px;"></div>
			
			<script>
				(function() {
					// Ensure chart data is ready
					var chartData = <?php echo wp_json_encode( $chart_data ); ?>;
					var chartLabels = <?php echo wp_json_encode( $chart_labels ); ?>;
					
					// Load ApexCharts if not already loaded
					if ( typeof ApexCharts === 'undefined' ) {
						var script = document.createElement( 'script' );
						script.src = 'https://cdn.jsdelivr.net/npm/apexcharts@3.45.0/dist/apexcharts.min.js';
						script.onload = function() {
							// Wait for DOM to be ready
							if ( document.readyState === 'loading' ) {
								document.addEventListener( 'DOMContentLoaded', drawChart );
							} else {
								drawChart();
							}
						};
						document.head.appendChild( script );
					} else {
						// Wait for DOM to be ready
						if ( document.readyState === 'loading' ) {
							document.addEventListener( 'DOMContentLoaded', drawChart );
						} else {
							drawChart();
						}
					}
					
					function drawChart() {
						// Verify element exists
						var chartElement = document.querySelector( '#bearmor-uptime-chart' );
						if ( ! chartElement ) {
							console.error( 'Bearmor: Chart element not found' );
							return;
						}
						var options = {
							chart: {
								type: 'bar',
								height: 165,
								sparkline: {
									enabled: false
								},
								toolbar: {
									show: false
								}
							},
							plotOptions: {
								bar: {
									columnWidth: '70%',
									borderRadius: 3,
									dataLabels: {
										enabled: false
									}
								}
							},
							series: [{
								name: 'Uptime %',
								data: chartData
							}],
							xaxis: {
								categories: chartLabels,
								axisBorder: {
									show: false
								},
								axisTicks: {
									show: false
								},
								labels: {
									show: false
								}
							},
							yaxis: {
								show: false,
								max: 100
							},
							colors: ['#7267EF'],
							grid: {
								show: false,
								padding: {
									top: 0,
									right: 0,
									bottom: 0,
									left: 0
								}
							},
							states: {
								hover: {
									filter: {
										type: 'none'
									}
								},
								active: {
									filter: {
										type: 'none'
									}
								}
							},
							tooltip: {
								theme: 'light',
								y: {
									formatter: function( value ) {
										return value + '%';
									}
								}
							}
						};
						
						var chart = new ApexCharts( document.querySelector( '#bearmor-uptime-chart' ), options );
						chart.render();
					}
				})();
			</script>
			
			<?php if ( $last_downtime ) : ?>
				<div class="bearmor-uptime-last-downtime" >
					<p style="margin: 0;">
						<strong>Last down:</strong> 
						<?php 
							$start_date = date( 'd.m.y H:i', strtotime( $last_downtime->start_time ) );
							$duration = $last_downtime->duration_minutes ? $last_downtime->duration_minutes . ' min' : 'ongoing';
							echo esc_html( $start_date ) . ' (' . esc_html( $duration ) . ')';
						?>
					</p>
				</div>
			<?php endif; ?>
			
			<div style="text-align: center; margin-top: 10px;">
				<button class="button button-secondary" onclick="bearmorShowUptimeHistory()" style="font-size: 11px;">
					📊 View History
				</button>
				<button class="button button-secondary" onclick="bearmorManualSync()" style="font-size: 11px; margin-left: 5px;">
					🔄 Sync Now
				</button>
			</div>
		<?php else : ?>
			<p class="bearmor-widget-description">24/7 uptime monitoring with instant alerts</p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="bearmor-widget-action bearmor-upgrade-btn">Upgrade to Pro</a>
		<?php endif; ?>
	</div>
</div>

<!-- Uptime History Modal -->
<div id="bearmor-uptime-history-modal" style="display: none; position: fixed; z-index: 999999; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">
	<div style="background-color: #fff; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 900px; max-height: 80vh; overflow-y: auto;">
		<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
			<h2 style="margin: 0;">📊 Uptime History (Last 30 Days)</h2>
			<button onclick="bearmorCloseUptimeHistory()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #666;">&times;</button>
		</div>
		
		<div id="bearmor-uptime-history-content">
			<p style="text-align: center; padding: 40px;">Loading history...</p>
		</div>
	</div>
</div>

<script>
function bearmorShowUptimeHistory() {
	document.getElementById('bearmor-uptime-history-modal').style.display = 'block';
	
	// Fetch uptime history via AJAX
	jQuery.ajax({
		url: ajaxurl,
		type: 'POST',
		data: {
			action: 'bearmor_get_uptime_history'
		},
		success: function(response) {
			if (response.success) {
				document.getElementById('bearmor-uptime-history-content').innerHTML = response.data.html;
			} else {
				document.getElementById('bearmor-uptime-history-content').innerHTML = '<p style="color: red;">Failed to load history.</p>';
			}
		},
		error: function() {
			document.getElementById('bearmor-uptime-history-content').innerHTML = '<p style="color: red;">Error loading history.</p>';
		}
	});
}

function bearmorCloseUptimeHistory() {
	document.getElementById('bearmor-uptime-history-modal').style.display = 'none';
}

function bearmorManualSync() {
	if (!confirm('Trigger manual uptime sync? Check error logs after.')) {
		return;
	}
	
	jQuery.ajax({
		url: ajaxurl,
		type: 'POST',
		data: {
			action: 'bearmor_manual_uptime_sync'
		},
		success: function(response) {
			if (response.success) {
				alert('Sync triggered! Check error logs for details.');
				location.reload();
			} else {
				alert('Sync failed: ' + response.data.message);
			}
		},
		error: function() {
			alert('AJAX error');
		}
	});
}

// Close modal when clicking outside
document.addEventListener('click', function(event) {
	var modal = document.getElementById('bearmor-uptime-history-modal');
	if (event.target === modal) {
		bearmorCloseUptimeHistory();
	}
});
</script>
