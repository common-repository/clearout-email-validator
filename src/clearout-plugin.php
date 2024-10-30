<?php
/**
 * Description. plugin module for clearout.
 *
 * @package clearout-email-validator
 */

// add clearout plugin setup page to the admin options page.
add_action( 'admin_menu', 'co_action_plugin_setup' );
add_action( 'admin_notices', 'co_action_admin_notice' );
add_action( 'wp_ajax_co_test_plugin_setting_action', 'co_test_plugin_setting_action' );
add_action( 'admin_init', 'co_action_plugin_admin_init' );
add_action( 'update_option_clearout_email_validator', 'co_action_update_user_plugin_settings_change', 1, 2 );
add_action( 'admin_init', 'co_reset_options' );

$clearout_options = get_option( 'clearout_email_validator' );

// add filters and actions to the supported forms.

// Contact Form7.
if ( ( isset( $clearout_options['cf7_on_off'] ) == 'on' ) && isset( $_POST['_wpcf7'] ) && is_plugin_active( 'contact-form-7/wp-contact-form-7.php' ) ) {
	add_filter( 'wpcf7_validate_email', 'clearout_wpcf7_custom_email_validator_filter', 1, 2 ); // Email field.
	add_filter( 'wpcf7_validate_email*', 'clearout_wpcf7_custom_email_validator_filter', 1, 2 ); // Req. Email field.
}

// Formiddable Form.
if ( ( isset( $clearout_options['fmf_on_off'] ) == 'on' ) && isset( $_POST['frm_action'] ) && is_plugin_active( 'formidable/formidable.php' ) ) {
	add_action( 'frm_validate_entry', 'clearout_frm_validate_entry', 1, 2 );
}

// Contact Form BWS.
if ( ( isset( $clearout_options['cfb_on_off'] ) == 'on' ) && is_plugin_active( 'contact-form-plugin/contact_form.php' ) && isset( $_POST['cntctfrm_contact_email'] ) ) {
	add_filter( 'cntctfrm_check_form', 'clearout_bws_validate_email', 1 );
}

// Ninja Form.
if ( ( 'on' == isset( $clearout_options['njf_on_off'] ) ) && ( isset( $_POST['action'] ) && 'nf_ajax_submit' == $_POST['action'] ) && is_plugin_active( 'ninja-forms/ninja-forms.php' ) ) {
	add_filter( 'ninja_forms_submit_data', 'clearout_ninja_email_validator', 1, 1 );
}

// Gravity Form.
if ( ( isset( $clearout_options['gvf_on_off'] ) == 'on' ) ) {
	add_filter( 'gform_field_validation', 'clearout_gvf_email_validator', 1, 4 );
}

// WordPress Registration Form.
if ( ( isset( $clearout_options['rgf_on_off'] ) == 'on' ) && isset( $_POST['wp-submit'] ) ) {
	add_action( 'registration_errors', 'clearout_email_validator_wprg', 1, 3 );
}

// WordPress Comment Form.
if ( ( isset( $clearout_options['cmf_on_off'] ) == 'on' ) ) {
	add_action( 'pre_comment_on_post', 'co_action_is_email_filter', 1 );
	add_action( 'comment_post', 'co_action_remove_is_email_filter', 1 );
}

// WPForm.
if ( ( isset( $clearout_options['wpf_on_off'] ) == 'on' ) ) {
	add_filter( 'wpforms_process_before', 'clearout_wpf_email_validator', 1, 2 );
}

// is_email hook.
if ( ( isset( $clearout_options['ise_on_off'] ) == 'on' ) ) { // Other plugins that used is_email.
	add_filter( 'is_email', 'clearout_email_validator_filter', 1 );
}

// Mailster Form.
if ( ( isset( $clearout_options['msf_on_off'] ) == 'on' ) ) {
	add_filter( 'mailster_verify_subscriber', 'clearout_mailster_email_validator', 1 );
}

// Woocommerce Checkout Form.
if ( ( isset( $clearout_options['chf_on_off'] ) == 'on' ) ) {
	add_filter( 'woocommerce_after_checkout_validation', 'clearout_woocom_checkout_validate_email', 1, 2 );
}

// ProMembership Form.
if ( ( isset( $clearout_options['pmp_on_off'] ) == 'on' ) ) {
	add_filter( 'pmpro_registration_checks', 'clearout_pmpro_signup_email_validate', 1, 2 );
}

// Elementor Form.
if ( ( isset( $clearout_options['elm_on_off'] ) == 'on' ) && is_plugin_active( 'elementor-pro/elementor-pro.php' ) ) {
	add_action( 'elementor_pro/forms/validation/email', 'clearout_elementor_email_validator', 1, 3 );
}

// Fluent Form.
if ( ( isset( $clearout_options['flf_on_off'] ) == 'on' ) ) {
	add_filter( 'fluentform_validate_input_item_input_email', 'clearout_fluent_email_validator', 1, 5 );
}

// WS Form.
if ( ( isset( $clearout_options['wsf_on_off'] ) == 'on' ) ) {
	add_filter( 'wsf_action_email_email_validate', 'clearout_wsf_email_validator', 1, 2 );
}

// WS Form.
if ( ( isset( $clearout_options['frm_on_off'] ) == 'on' ) ) {
	add_filter( 'forminator_custom_form_submit_errors', 'clearout_forminator_email_validator', 1, 3 );
}

/**
 * Action Handlers.
 */
function co_action_is_email_filter() {
	add_filter( 'is_email', 'clearout_email_validator_filter', 1, 3 );
}

/**
 * Action Handlers.
 */
function co_action_remove_is_email_filter() {
	remove_filter( 'is_email', 'clearout_email_validator_filter', 1, 3 );
}
