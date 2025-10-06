<?php
/**
 * Hardening Class
 *
 * @package Bearmor_Security
 */

class Bearmor_Hardening {

	/**
	 * Initialize hooks
	 */
	public static function init() {
		// Security headers
		if ( get_option( 'bearmor_header_x_frame', true ) ) {
			add_action( 'send_headers', array( __CLASS__, 'add_x_frame_header' ) );
		}
		if ( get_option( 'bearmor_header_content_type', true ) ) {
			add_action( 'send_headers', array( __CLASS__, 'add_content_type_header' ) );
		}
		if ( get_option( 'bearmor_header_referrer', true ) ) {
			add_action( 'send_headers', array( __CLASS__, 'add_referrer_header' ) );
		}
		if ( get_option( 'bearmor_header_permissions', true ) ) {
			add_action( 'send_headers', array( __CLASS__, 'add_permissions_header' ) );
		}
		if ( get_option( 'bearmor_header_xss', true ) ) {
			add_action( 'send_headers', array( __CLASS__, 'add_xss_header' ) );
		}
		
		// Hide WP version
		if ( get_option( 'bearmor_hide_wp_version', false ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		
		// Block user enumeration
		if ( get_option( 'bearmor_block_user_enum', false ) ) {
			add_action( 'init', array( __CLASS__, 'block_user_enumeration' ) );
		}
		
		// Disable verbose login errors
		if ( get_option( 'bearmor_disable_login_errors', false ) ) {
			add_filter( 'login_errors', array( __CLASS__, 'generic_login_error' ) );
		}
		
		// Disable XML-RPC
		if ( get_option( 'bearmor_disable_xmlrpc', false ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_xmlrpc_server_class', array( __CLASS__, 'disable_xmlrpc_completely' ) );
		}
		
		// Force SSL
		if ( get_option( 'bearmor_force_ssl', false ) && is_ssl() ) {
			add_action( 'template_redirect', array( __CLASS__, 'force_ssl_redirect' ) );
		}
	}

	/**
	 * Security header functions
	 */
	public static function add_x_frame_header() {
		if ( ! is_admin() ) {
			header( 'X-Frame-Options: SAMEORIGIN' );
		}
	}

	public static function add_content_type_header() {
		if ( ! is_admin() ) {
			header( 'X-Content-Type-Options: nosniff' );
		}
	}

	public static function add_referrer_header() {
		if ( ! is_admin() ) {
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		}
	}

	public static function add_permissions_header() {
		if ( ! is_admin() ) {
			header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
		}
	}

	public static function add_xss_header() {
		if ( ! is_admin() ) {
			header( 'X-XSS-Protection: 1; mode=block' );
		}
	}

	/**
	 * Block user enumeration
	 */
	public static function block_user_enumeration() {
		if ( ! is_admin() && isset( $_GET['author'] ) && ! empty( $_GET['author'] ) ) {
			wp_die( 'Forbidden', 'Forbidden', array( 'response' => 403 ) );
		}
	}

	/**
	 * Generic login error message
	 */
	public static function generic_login_error() {
		return 'Login failed. Please check your credentials.';
	}

	/**
	 * Disable XML-RPC completely
	 */
	public static function disable_xmlrpc_completely() {
		wp_die( 'XML-RPC services are disabled on this site.', 'XML-RPC Disabled', array( 'response' => 403 ) );
	}

	/**
	 * Force SSL redirect
	 */
	public static function force_ssl_redirect() {
		if ( ! is_ssl() && ! is_admin() ) {
			wp_redirect( 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], 301 );
			exit;
		}
	}

	/**
	 * Check if SSL is available
	 */
	public static function is_ssl_available() {
		return is_ssl();
	}

	/**
	 * Check if file editing is disabled
	 */
	public static function is_file_editing_disabled() {
		return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
	}

	/**
	 * Check if WP_DEBUG is enabled
	 */
	public static function is_debug_enabled() {
		return defined( 'WP_DEBUG' ) && WP_DEBUG;
	}

	/**
	 * Get hardening status
	 */
	public static function get_hardening_status() {
		return array(
			'header_x_frame'        => (bool) get_option( 'bearmor_header_x_frame', true ),
			'header_content_type'   => (bool) get_option( 'bearmor_header_content_type', true ),
			'header_referrer'       => (bool) get_option( 'bearmor_header_referrer', true ),
			'header_permissions'    => (bool) get_option( 'bearmor_header_permissions', true ),
			'header_xss'            => (bool) get_option( 'bearmor_header_xss', true ),
			'hide_wp_version'       => (bool) get_option( 'bearmor_hide_wp_version', false ),
			'block_user_enum'       => (bool) get_option( 'bearmor_block_user_enum', false ),
			'disable_login_errors'  => (bool) get_option( 'bearmor_disable_login_errors', false ),
			'disable_xmlrpc'        => (bool) get_option( 'bearmor_disable_xmlrpc', false ),
			'force_ssl'             => (bool) get_option( 'bearmor_force_ssl', false ),
			'file_editing_disabled' => self::is_file_editing_disabled(),
			'ssl_available'         => self::is_ssl_available(),
			'debug_disabled'        => ! self::is_debug_enabled(),
		);
	}

	/**
	 * Save all hardening settings
	 */
	public static function save_settings( $post_data ) {
		// Save database options
		update_option( 'bearmor_header_x_frame', isset( $post_data['header_x_frame'] ) );
		update_option( 'bearmor_header_content_type', isset( $post_data['header_content_type'] ) );
		update_option( 'bearmor_header_referrer', isset( $post_data['header_referrer'] ) );
		update_option( 'bearmor_header_permissions', isset( $post_data['header_permissions'] ) );
		update_option( 'bearmor_header_xss', isset( $post_data['header_xss'] ) );
		update_option( 'bearmor_hide_wp_version', isset( $post_data['hide_wp_version'] ) );
		update_option( 'bearmor_block_user_enum', isset( $post_data['block_user_enum'] ) );
		update_option( 'bearmor_disable_login_errors', isset( $post_data['disable_login_errors'] ) );
		update_option( 'bearmor_disable_xmlrpc', isset( $post_data['disable_xmlrpc'] ) );
		update_option( 'bearmor_force_ssl', isset( $post_data['force_ssl'] ) );
		
		// Handle file editing (modifies wp-config.php)
		$file_editing_requested = isset( $post_data['file_editing_disabled'] );
		$file_editing_current = self::is_file_editing_disabled();
		
		if ( $file_editing_requested && ! $file_editing_current ) {
			self::disable_file_editing();
		} elseif ( ! $file_editing_requested && $file_editing_current ) {
			self::enable_file_editing();
		}
		
		return true;
	}

	/**
	 * Disable file editing - adds line to wp-config.php
	 */
	private static function disable_file_editing() {
		$wp_config = ABSPATH . 'wp-config.php';
		
		if ( ! file_exists( $wp_config ) || ! is_writable( $wp_config ) ) {
			return false;
		}
		
		$config_content = file_get_contents( $wp_config );
		
		// Already exists?
		if ( strpos( $config_content, 'DISALLOW_FILE_EDIT' ) !== false ) {
			return true;
		}
		
		// Find marker
		$marker = "/* That's all, stop editing!";
		$position = strpos( $config_content, $marker );
		
		if ( $position === false ) {
			return false;
		}
		
		// Add the line
		$new_line = "// Disable file editing (added by Bearmor Security)\ndefine( 'DISALLOW_FILE_EDIT', true );\n\n";
		$config_content = substr_replace( $config_content, $new_line, $position, 0 );
		
		return file_put_contents( $wp_config, $config_content ) !== false;
	}

	/**
	 * Enable file editing - removes line from wp-config.php
	 */
	private static function enable_file_editing() {
		$wp_config = ABSPATH . 'wp-config.php';
		
		if ( ! file_exists( $wp_config ) || ! is_writable( $wp_config ) ) {
			return false;
		}
		
		$config_content = file_get_contents( $wp_config );
		
		// Doesn't exist?
		if ( strpos( $config_content, 'DISALLOW_FILE_EDIT' ) === false ) {
			return true;
		}
		
		// Remove the line
		$config_content = preg_replace(
			'/\/\/ Disable file editing \(added by Bearmor Security\)\s*\ndefine\(\s*[\'"]DISALLOW_FILE_EDIT[\'"]\s*,\s*true\s*\)\s*;\s*\n*/',
			'',
			$config_content
		);
		
		return file_put_contents( $wp_config, $config_content ) !== false;
	}

	/**
	 * Apply recommended hardening
	 */
	public static function apply_recommended() {
		update_option( 'bearmor_header_x_frame', true );
		update_option( 'bearmor_header_content_type', true );
		update_option( 'bearmor_header_referrer', true );
		update_option( 'bearmor_header_permissions', true );
		update_option( 'bearmor_header_xss', true );
		update_option( 'bearmor_hide_wp_version', true );
		update_option( 'bearmor_block_user_enum', true );
		update_option( 'bearmor_disable_login_errors', true );
		
		if ( self::is_ssl_available() ) {
			update_option( 'bearmor_force_ssl', true );
		}
	}

	/**
	 * Disable all hardening
	 */
	public static function disable_all() {
		update_option( 'bearmor_header_x_frame', false );
		update_option( 'bearmor_header_content_type', false );
		update_option( 'bearmor_header_referrer', false );
		update_option( 'bearmor_header_permissions', false );
		update_option( 'bearmor_header_xss', false );
		update_option( 'bearmor_hide_wp_version', false );
		update_option( 'bearmor_block_user_enum', false );
		update_option( 'bearmor_disable_login_errors', false );
		update_option( 'bearmor_disable_xmlrpc', false );
		update_option( 'bearmor_force_ssl', false );
	}
}
