<?php
/**
 * Plugin Name:  Clearout Email Validator
 * Plugin URL:   https://developer.wordpress.org/plugins/clearout-email-validator
 * Description:  This plugin seamlessly integrated with all major forms to validate the user's given email address in real-time. Under the hood, this plugin use Clearout API to perform 20+ refined validation checks to determine the status of the email address, and thus helps capturing only the valid leads to maintain high quality mailing list.
 * Version:      3.1.5
 * Author:       Clearout.io
 * Author URI:   https://clearout.io
 * License:      GNU
 * License URI:  https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package clearout-email-validator
 */

// plugin version.
define( 'CLEAROUT_PLUGIN_VERSION', '3.1.5' );
define( 'CLEAROUT_RESULT_CACHED_TIMEOUT', 3600 );
define( 'CLEAROUT_BASE_API_URL', 'https://api.clearout.io/v2/' );
define( 'CLEAROUT_EMAIL_VERIFY_API_URL', CLEAROUT_BASE_API_URL . 'wordpress/email_verify?v=' . CLEAROUT_PLUGIN_VERSION );
define( 'CLEAROUT_PLUGIN_SETTINGS_API_URL', CLEAROUT_BASE_API_URL . 'wordpress/co_wp_setting_changed?v=' . CLEAROUT_PLUGIN_VERSION );
define( 'CLEAROUT_PLUGIN_DEACTIVATED_API_URL', CLEAROUT_BASE_API_URL . 'wordpress/co_wp_deactivated?v=' . CLEAROUT_PLUGIN_VERSION );
define( 'CLEAROUT_PLUGIN_ACTIVATED_API_URL', CLEAROUT_BASE_API_URL . 'wordpress/co_wp_activated?v=' . CLEAROUT_PLUGIN_VERSION );
define( 'CLEAROUT_GET_AVAILABLE_CREDITS_API_URL', CLEAROUT_BASE_API_URL . 'email_verify/getcredits' );
define( 'CLEAROUT_TEST_PLUGIN_SOURCE', 'co-test-plugin' );
define( 'CLEAROUT_VERIFICATION_EMAIL_WHITELISTED_SUBSTATUS_CODE', 601 );
define( 'CLEAROUT_VERIFICATION_DOMAIN_WHITELISTED_SUBSTATUS_CODE', 603 );
define( 'CLEAROUT_VERIFICATION_TLD_WHITELISTED_SUBSTATUS_CODE', 607 );
define( 'CLEAROUT_VERIFICATION_ACCOUNT_WHITELISTED_SUBSTATUS_CODE', 609 );
define( 'CLEAROUT_UNAUTHORIZED_STATUS_CODE', 401 );
define( 'CLEAROUT_HTTP_OK_STATUS_CODE', 200 );
define( 'CLEAROUT_IGNORE_VALIDATION_IDENTIFIER_REGEX', '/^clearout_skip_validation/i' );

require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once dirname( __FILE__ ) . '/src/clearout-plugin.php';
require_once dirname( __FILE__ ) . '/src/clearout-validator.php';
require_once dirname( __FILE__ ) . '/src/clearout-plugin-page-settings.php';
register_activation_hook( __FILE__, 'co_hook_plugin_activate' );
register_deactivation_hook( __FILE__, 'co_hook_plugin_deactivate' );
