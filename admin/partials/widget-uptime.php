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

// Generate 7-day uptime data for chart (calculate per day from downtime_events)
$chart_data = array();
$chart_labels = array();
for ( $i = 6; $i >= 0; $i-- ) {
	$date = date( 'M d', strtotime( "-$i days" ) );
	$day_start = strtotime( date( 'Y-m-d', strtotime( "-$i days" ) ) );
	$day_end = $day_start + 86400;
	
	// Calculate uptime for this day
	$day_downtime = 0;
	foreach ( $uptime_stats['downtime_events'] as $event ) {
		$event_start = strtotime( $event->start_time );
		$event_end = $event->end_time ? strtotime( $event->end_time ) : time();
		
		// Check if event overlaps with this day
		if ( $event_start < $day_end && $event_end > $day_start ) {
			$overlap_start = max( $event_start, $day_start );
			$overlap_end = min( $event_end, $day_end );
			$day_downtime += $overlap_end - $overlap_start;
		}
	}
	
	$day_uptime = max( 0, 100 - round( ( $day_downtime / 86400 ) * 100, 0 ) );
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
					// Load ApexCharts if not already loaded
					if ( typeof ApexCharts === 'undefined' ) {
						var script = document.createElement( 'script' );
						script.src = 'https://cdn.jsdelivr.net/npm/apexcharts@3.45.0/dist/apexcharts.min.js';
						script.onload = function() {
							drawChart();
						};
						document.head.appendChild( script );
					} else {
						drawChart();
					}
					
					function drawChart() {
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
								data: <?php echo wp_json_encode( $chart_data ); ?>
							}],
							xaxis: {
								categories: <?php echo wp_json_encode( $chart_labels ); ?>,
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
		<?php else : ?>
			<p class="bearmor-widget-description">24/7 uptime monitoring with instant alerts</p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="bearmor-widget-action bearmor-upgrade-btn">Upgrade to Pro</a>
		<?php endif; ?>
	</div>
</div>
