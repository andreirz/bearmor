<?php
/**
 * Uploads Scanner Class
 * Scans wp-content/uploads for malicious files
 *
 * @package Bearmor_Security
 */

class Bearmor_Uploads_Scanner {

	/**
	 * Dangerous file extensions
	 */
	private static $dangerous_extensions = array(
		'php', 'php3', 'php4', 'php5', 'php7', 'phtml',
		'phar', 'phps', 'suspected', 'inc',
	);

	/**
	 * Scan uploads directory
	 *
	 * @param int $batch_size Number of files per batch
	 * @param int $offset Starting offset
	 * @return array Results
	 */
	public static function scan_batch( $batch_size = 50, $offset = 0 ) {
		$upload_dir = wp_upload_dir();
		$base_dir = $upload_dir['basedir'];
		
		$results = array();
		$files = self::get_files( $base_dir, $batch_size, $offset );

		foreach ( $files as $file ) {
			$threat = self::check_file( $file );
			if ( $threat ) {
				$results[] = array(
					'type'     => 'upload_file',
					'file'     => $file,
					'location' => str_replace( ABSPATH, '', $file ),
					'pattern'  => $threat['pattern'],
					'matched'  => $threat['matched'],
					'severity' => $threat['severity'],
				);
			}
		}

		return $results;
	}

	/**
	 * Get files from directory recursively
	 *
	 * @param string $dir Directory path
	 * @param int $limit Limit
	 * @param int $offset Offset
	 * @return array File paths
	 */
	private static function get_files( $dir, $limit = 50, $offset = 0 ) {
		// Get all files (no static cache - causes issues with fresh scans)
		$all_files = array();
		
		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() ) {
					$all_files[] = $file->getPathname();
				}
			}
		} catch ( Exception $e ) {
			// Directory doesn't exist or can't be read
			return array();
		}

		return array_slice( $all_files, $offset, $limit );
	}

	/**
	 * Check file for threats
	 *
	 * @param string $file File path
	 * @return array|false Threat details or false
	 */
	private static function check_file( $file ) {
		$filename = basename( $file );
		$extension = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );

		// Check 1: Direct PHP file
		if ( in_array( $extension, self::$dangerous_extensions ) ) {
			return array(
				'pattern'  => 'PHP file in uploads',
				'matched'  => $filename,
				'severity' => 'critical',
			);
		}

		// Check 2: Double extension (e.g., image.jpg.php)
		if ( preg_match( '/\.(jpg|jpeg|png|gif|webp)\.(' . implode( '|', self::$dangerous_extensions ) . ')$/i', $filename ) ) {
			return array(
				'pattern'  => 'Double extension',
				'matched'  => $filename,
				'severity' => 'critical',
			);
		}

		// Check 3: Polyglot files (image with embedded PHP)
		if ( preg_match( '/\.(jpg|jpeg|png|gif|webp|svg)$/i', $filename ) ) {
			// Only check small files (< 5MB) for performance
			if ( filesize( $file ) < 5 * 1024 * 1024 ) {
				$content = file_get_contents( $file, false, null, 0, 1024 ); // Read first 1KB
				
				// Check for PHP opening tags
				if ( preg_match( '/<\?php|<\?=|<script[^>]*language\s*=\s*["\']?php["\']?/i', $content ) ) {
					return array(
						'pattern'  => 'PHP code in image file',
						'matched'  => 'Polyglot file detected',
						'severity' => 'critical',
					);
				}
			}
		}

		// Check 4: Suspicious filenames
		$suspicious_names = array( 'shell', 'backdoor', 'c99', 'r57', 'webshell', 'bypass', 'exploit' );
		foreach ( $suspicious_names as $name ) {
			if ( stripos( $filename, $name ) !== false ) {
				return array(
					'pattern'  => 'Suspicious filename',
					'matched'  => $filename,
					'severity' => 'high',
				);
			}
		}

		return false;
	}

	/**
	 * Get total file count
	 *
	 * @return int File count
	 */
	public static function get_file_count() {
		$upload_dir = wp_upload_dir();
		$base_dir = $upload_dir['basedir'];
		
		$count = 0;
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $base_dir, RecursiveDirectoryIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$count++;
			}
		}

		return $count;
	}

	/**
	 * Quarantine a file
	 *
	 * @param string $file File path
	 * @return bool Success
	 */
	public static function quarantine_file( $file ) {
		$quarantine_dir = WP_CONTENT_DIR . '/bearmor-quarantine/uploads/';
		
		if ( ! file_exists( $quarantine_dir ) ) {
			wp_mkdir_p( $quarantine_dir );
		}

		$filename = basename( $file );
		$destination = $quarantine_dir . time() . '_' . $filename;

		return rename( $file, $destination );
	}

	/**
	 * Delete a file
	 *
	 * @param string $file File path
	 * @return bool Success
	 */
	public static function delete_file( $file ) {
		if ( file_exists( $file ) ) {
			return unlink( $file );
		}
		return false;
	}
}
