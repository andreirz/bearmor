<?php
/**
 * Batch Processor - Handle large scans in chunks
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Batch_Processor {

	const BATCH_SIZE = 100;
	const TRANSIENT_TIMEOUT = HOUR_IN_SECONDS;

	/**
	 * Start batch processing
	 *
	 * @param string $scan_type 'malware' or 'deep'
	 * @param array  $files List of files to scan
	 * @return array Batch info
	 */
	public static function start_batch( $scan_type, $files ) {
		$batch_id = uniqid( 'batch_' );
		$total_files = count( $files );
		$total_batches = ceil( $total_files / self::BATCH_SIZE );

		$batch_data = array(
			'id'            => $batch_id,
			'scan_type'     => $scan_type,
			'files'         => $files,
			'total_files'   => $total_files,
			'total_batches' => $total_batches,
			'current_batch' => 0,
			'processed'     => 0,
			'results'       => array(),
			'started_at'    => current_time( 'mysql' ),
		);

		// Store in transient
		set_transient( 'bearmor_batch_' . $batch_id, $batch_data, self::TRANSIENT_TIMEOUT );

		error_log( 'BEARMOR Batch: Started batch ' . $batch_id . ' with ' . $total_files . ' files' );

		return $batch_data;
	}

	/**
	 * Process next batch
	 *
	 * @param string $batch_id Batch ID
	 * @return array|WP_Error Batch data or error
	 */
	public static function process_next_batch( $batch_id ) {
		$batch_data = get_transient( 'bearmor_batch_' . $batch_id );

		if ( ! $batch_data ) {
			return new WP_Error( 'batch_not_found', 'Batch not found or expired' );
		}

		$current_batch = $batch_data['current_batch'];
		$start_index = $current_batch * self::BATCH_SIZE;
		$end_index = min( $start_index + self::BATCH_SIZE, $batch_data['total_files'] );

		// Get files for this batch
		$batch_files = array_slice( $batch_data['files'], $start_index, self::BATCH_SIZE );

		error_log( 'BEARMOR Batch: Processing batch ' . ( $current_batch + 1 ) . '/' . $batch_data['total_batches'] );

		// Process files based on scan type
		$results = array();
		if ( $batch_data['scan_type'] === 'malware' ) {
			$results = self::process_malware_batch( $batch_files );
		} elseif ( $batch_data['scan_type'] === 'deep' ) {
			$results = self::process_deep_batch( $batch_files );
		}

		// Update batch data
		$batch_data['current_batch']++;
		$batch_data['processed'] = $end_index;
		$batch_data['results'] = array_merge( $batch_data['results'], $results );

		// Check if done
		$is_complete = ( $batch_data['current_batch'] >= $batch_data['total_batches'] );

		if ( $is_complete ) {
			$batch_data['completed_at'] = current_time( 'mysql' );
			error_log( 'BEARMOR Batch: Batch ' . $batch_id . ' completed' );
		}

		// Update transient
		set_transient( 'bearmor_batch_' . $batch_id, $batch_data, self::TRANSIENT_TIMEOUT );

		// Calculate percentage
		$percentage = $batch_data['total_files'] > 0 ? round( ( $batch_data['processed'] / $batch_data['total_files'] ) * 100 ) : 0;

		return array(
			'batch_id'    => $batch_id,
			'current'     => $batch_data['current_batch'],
			'total'       => $batch_data['total_batches'],
			'processed'   => $batch_data['processed'],
			'total_files' => $batch_data['total_files'],
			'percentage'  => $percentage,
			'is_complete' => $is_complete,
			'results'     => $results,
		);
	}

	/**
	 * Process malware batch
	 *
	 * @param array $files Files to scan
	 * @return array Results
	 */
	private static function process_malware_batch( $files ) {
		if ( ! class_exists( 'Bearmor_Malware_Scanner' ) ) {
			return array();
		}

		$results = array();
		foreach ( $files as $file ) {
			$threats = Bearmor_Malware_Scanner::scan_file( $file );
			if ( ! empty( $threats ) ) {
				$results[ $file ] = $threats;
			}
		}

		return $results;
	}

	/**
	 * Process deep scan batch
	 *
	 * @param array $files Files to scan
	 * @return array Results
	 */
	private static function process_deep_batch( $files ) {
		if ( ! class_exists( 'Bearmor_DB_Scanner' ) ) {
			return array();
		}

		$results = array();
		foreach ( $files as $file ) {
			$threats = Bearmor_DB_Scanner::scan_file( $file );
			if ( ! empty( $threats ) ) {
				$results[ $file ] = $threats;
			}
		}

		return $results;
	}

	/**
	 * Get batch progress
	 *
	 * @param string $batch_id Batch ID
	 * @return array|WP_Error Progress data or error
	 */
	public static function get_progress( $batch_id ) {
		$batch_data = get_transient( 'bearmor_batch_' . $batch_id );

		if ( ! $batch_data ) {
			return new WP_Error( 'batch_not_found', 'Batch not found or expired' );
		}

		$percentage = round( ( $batch_data['processed'] / $batch_data['total_files'] ) * 100 );

		return array(
			'batch_id'    => $batch_id,
			'current'     => $batch_data['current_batch'],
			'total'       => $batch_data['total_batches'],
			'processed'   => $batch_data['processed'],
			'total_files' => $batch_data['total_files'],
			'percentage'  => $percentage,
			'is_complete' => ( $batch_data['current_batch'] >= $batch_data['total_batches'] ),
		);
	}

	/**
	 * Cancel batch
	 *
	 * @param string $batch_id Batch ID
	 */
	public static function cancel_batch( $batch_id ) {
		delete_transient( 'bearmor_batch_' . $batch_id );
		error_log( 'BEARMOR Batch: Cancelled batch ' . $batch_id );
	}

	/**
	 * Get batch results
	 *
	 * @param string $batch_id Batch ID
	 * @return array|WP_Error Results or error
	 */
	public static function get_results( $batch_id ) {
		$batch_data = get_transient( 'bearmor_batch_' . $batch_id );

		if ( ! $batch_data ) {
			return new WP_Error( 'batch_not_found', 'Batch not found or expired' );
		}

		return $batch_data['results'];
	}
}
