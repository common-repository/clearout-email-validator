<?php
/**
 * Description. Uninstall module for clearout.
 *
 * @package clearout-email-validator
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

delete_option( 'clearout_email_validator' );
delete_option( 'CLEAROUT_PLUGIN_VERSION' );

wp_cache_flush();
