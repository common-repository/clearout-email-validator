<?php
/**
 * Description. Validator module for Clearout.
 *
 * @package clearout-email-validator
 */

/**
 * Public methods called by ajax.php.
 */
function co_test_plugin_setting_action() {

	// Nonce Checks.
	check_admin_referer( 'test-email-nonce' ); // Verify nonce.
	if ( ! current_user_can( 'manage_options' ) ) { // Check user permissions.
		wp_die( esc_html__( 'You do not have sufficient permissions to perform this action.' ) );
	}

	$clearout_options = get_option( 'clearout_email_validator' );
	// Check if API token is set eg. When plugin is installed for first time and api token isnt set.
	if ( ! isset( $clearout_options['api_key'] ) || empty( $clearout_options['api_key'] ) || ! isset( $_POST['clearout_email'] ) ) {
		$response['status']         = 'success';
		$response['data']           = array();
		$response['data']['reason'] = esc_html__( 'API token not set, please set the token above and apply the settings' );
		$response['data']['status'] = false;
		wp_send_json( $response );
		exit();
	}

	$sanitized_email = sanitize_email( wp_unslash( $_POST['clearout_email'] ) );
	$response        = array();
	// Check if sanitised email has returned empty i.e syntax errors.
	if ( empty( $sanitized_email ) ) {
		$response['status']         = 'success';
		$response['data']           = array();
		$response['data']['reason'] = ( _check_custom_error_msg_exist( $clearout_options ) ) ? esc_html( $clearout_options['custom_invalid_error'] ) : esc_html__( 'You have entered an invalid email address, Please try again with a valid email address' );
		$response['data']['status'] = false;
		wp_send_json( $response );
		exit();
	}
	$validation_result = _co_email_validation( $sanitized_email, $clearout_options, CLEAROUT_TEST_PLUGIN_SOURCE );
	$message           = 'You have entered valid email address';
	if ( 'valid_email' != $validation_result['reason'] ) {
		$message = _get_error_message( $validation_result['reason'] );
	}
	$message                     = ( isset( $clearout_options['custom_invalid_error'] ) && 'valid_email' != $validation_result['reason'] && '' != trim( $clearout_options['custom_invalid_error'] ) ) ? $clearout_options['custom_invalid_error'] : $message;
	$validation_result['reason'] = $message;
	// compose response object.
	$response['status'] = 'success';
	$response['data']   = $validation_result;
	wp_send_json( $response );
	exit();
}

/**
 * Method to check if there is any custom error msg set and if it isnt empty after trimmed.
 *
 * @param mixed $clearout_options The clearout options.
 */
function _check_custom_error_msg_exist( $clearout_options ) {
	$ret = false;
	if ( isset( $clearout_options['custom_invalid_error'] ) && ! empty( trim( $clearout_options['custom_invalid_error'] ) ) ) {
		$ret = true;
	}
	return $ret;
}

/**
 * Get Current page URL.
 */
function _get_current_page_url() {
	$page_url = '';
	try { // try to get full url if possible?
		if ( isset( $_SERVER['HTTP_REFERER'] ) ) {
			$page_url = sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) );
		}
	} catch ( Exception $e ) {
		$page_url = get_site_url();
	}
	return $page_url;
}

/**
 * Is Url allowed for validation.
 *
 * @param mixed $clearout_options The clearout options.
 * @param mixed $page_url Then page Url.
 */
function _is_url_allowed_for_validation( $clearout_options, $page_url ) {
	$is_validation_allowed = false;
	try {
		// Parse the URL and remove the query parameters
		$parsed_url = parse_url( $page_url );
		$clean_url  = untrailingslashit( $parsed_url['scheme'] . '://' . $parsed_url['host'] . $parsed_url['path'] );

		$filter_url_array = explode( ',', $clearout_options['inclusion_filter_urls'] );
		if ( in_array( $clean_url, $filter_url_array, true ) ) {
			$is_validation_allowed = true;
		}
	} catch ( Exception $e ) {
		$is_validation_allowed = false;
	}
	return $is_validation_allowed;
}

/**
 * Find Users IP.
 *
 */
function _get_user_ip() {
	foreach ( array( 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR' ) as $key ) {
		if ( array_key_exists( $key, $_SERVER ) === true ) {
			foreach ( explode( ',', $_SERVER[ $key ] ) as $ip ) {
				$ip = trim( $ip );

				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
					return $ip;
				}
			}
		}
	}
}

/**
 * Is Url allowed for validation.
 *
 * @param mixed $clearout_options The clearout options.
 * @param mixed $page_url Then page Url.
 */
function _is_url_disallowed_for_validation( $clearout_options, $page_url ) {
	$is_validation_allowed = true;
	try {
		// Parse the URL and remove the query parameters
		$parsed_url = parse_url( $page_url );
		$clean_url  = untrailingslashit( $parsed_url['scheme'] . '://' . $parsed_url['host'] . $parsed_url['path'] );

		$filter_url_array = explode( ',', $clearout_options['exclusion_filter_urls'] );
		if ( in_array( $clean_url, $filter_url_array, true ) ) {
			$is_validation_allowed = false;
		}
	} catch ( Exception $e ) {
		$is_validation_allowed = true;
	}
	return $is_validation_allowed;
}

/**
 * Main Co Verify method.
 *
 * @param mixed $email_address The Email address.
 * @param mixed $api_key Api key.
 * @param mixed $timeout Timeout in seconds.
 * @param mixed $clearout_form_source Form Source.
 * @param mixed $use_cache Can use Cache.
 * @param mixed $clearout_options the clearout options.
 */
function _co_verify_email( $email_address, $api_key, $timeout, $clearout_form_source, $use_cache, $page_url ) {
	$data = null;
	try {
		global $wp;
		
		// Get Clients IP
		$client_ip = _get_user_ip();

		// Now we need to send the data to CLEAROUT API Token and return back the result.
		$url  = CLEAROUT_EMAIL_VERIFY_API_URL . '&r=fs&source=wordpress&fn=' . $clearout_form_source . '&pu=' . rawurlencode( $page_url );
		$args = array(
			'method'      => 'POST',
			'data_format' => 'body',
			'headers'     => array(
				'Content-Type'  => 'application/json',
				'Authorization' => 'Bearer:' . str_replace( ' ', '', $api_key ),
				'X-Client-IP'   => $client_ip
			),
			'body'        => wp_json_encode(
				array(
					'email'   => $email_address,
					'timeout' => $timeout * 1000,
				)
			),
			'timeout'     => $timeout + 2, // http request timeout with 2 secs grace interval.
		);

		// Now we used WordPress custom HTTP API method to get the result from CLEAROUT API.
		$results       = wp_remote_post( $url, $args );
		$response_code = wp_remote_retrieve_response_code( $results );
		if ( ! is_wp_error( $results ) ) {
			$body = wp_remote_retrieve_body( $results );
			// Decode the return json results and return the data.
			$data = json_decode( $body, true );
		}

		// Set transient for response verified email only if resp status === 200.
		$cache_key = 'clearout_' . strtolower( $email_address );
		if ( true == $use_cache && CLEAROUT_HTTP_OK_STATUS_CODE == $response_code && ! empty( $data['data'] ) ) {
			set_transient( $cache_key, $data, CLEAROUT_RESULT_CACHED_TIMEOUT );
		}
	} catch ( Exception $e ) {
		$data = null;
	}

	return $data;
}


/**
 * Is role email.
 *
 * @param mixed $email_result EV Result object.
 */
function _co_is_role_email( $email_result ) {
	$is_role = false;
	if ( 'yes' == $email_result['data']['role'] ) {
		$is_role = true;
	}
	return $is_role;
}

/**
 * Is Free email.
 *
 * @param mixed $email_result Ev Result Object.
 */
function _co_is_free( $email_result ) {
	$is_free = false;
	if ( 'yes' == $email_result['data']['free'] ) {
		$is_free = true;
	}
	return $is_free;
}

/**
 * Is Disposable email
 *
 * @param mixed $email_result Ev Result object.
 */
function _co_is_disposable( $email_result ) {
	$is_disposable = false;
	if ( 'yes' == $email_result['data']['disposable'] ) {
		$is_disposable = true;
	}
	return $is_disposable;
}

/**
 * Is Gibberish email
 *
 * @param mixed $email_result Ev Result object.
 */
function _co_is_gibberish( $email_result ) {
	$is_gibberish = false;
	if ( 'yes' == $email_result['data']['gibberish'] ) {
		$is_gibberish = true;
	}
	return $is_gibberish;
}

/**
 * Is sts email
 *
 * @param mixed $email_result Ev Result object.
 */
function _co_is_sts( $email_result ) {
	$is_sts = false;
	if ( 'yes' == $email_result['data']['safe_to_send'] ) {
		$is_sts = true;
	}
	return $is_sts;
}

/**
 * Email Validation method
 *
 * @param mixed $email Email.
 * @param mixed $clearout_options Co Options.
 * @param mixed $clearout_form_source Form Source.
 */
function _co_email_validation( $email, $clearout_options, $clearout_form_source ) {
	$clearout_validation_result = array();
	$use_cache                  = true;
	$email_result               = null;

	$page_url = _get_current_page_url();

	// Check to See if req is from ADmin Pages? If so return immediately, we dont want to ev
	// the Strpos check is introduced to make sure even if Rest API is called from admin page it shud not trigger EV
	if ( (is_admin() || strpos($page_url, get_admin_url()) === 0) && CLEAROUT_TEST_PLUGIN_SOURCE != $clearout_form_source ) {
		return $clearout_validation_result;
	}

	// Check if the page_url is
	if ( CLEAROUT_TEST_PLUGIN_SOURCE != $clearout_form_source && ! empty( $clearout_options['exclusion_filter_urls'] ) && ! _is_url_disallowed_for_validation( $clearout_options, $page_url ) ) {
		return $clearout_validation_result;
	}

	// Check if the page_url is part of allowed URL list, if so return immediately.
	if ( CLEAROUT_TEST_PLUGIN_SOURCE != $clearout_form_source && ! empty( $clearout_options['inclusion_filter_urls'] ) && ! _is_url_allowed_for_validation( $clearout_options, $page_url ) ) {
		return $clearout_validation_result;
	}

	// dont use cache for test plugin call.
	if ( CLEAROUT_TEST_PLUGIN_SOURCE === $clearout_form_source ) {
		$use_cache = false;
	}

	// EV Transient Cache check if data available in cache  use cache is set
	if ( true == $use_cache ) {
		$cache_key   = 'clearout_' . strtolower( $email );
		$cache_value = get_transient( $cache_key );
		if ( $cache_value ) {
			$email_result = $cache_value;
		}
	}

	if ( empty( $email_result ) ) {
		$email_result = _co_verify_email( $email, $clearout_options['api_key'], $clearout_options['timeout'], $clearout_form_source, $use_cache, $page_url );
	}

	// Check if valid API Token is present (Only for the 'co-test-plugin' form).
	if (
		CLEAROUT_TEST_PLUGIN_SOURCE == $clearout_form_source &&
		'failed' == $email_result['status'] && 1000 == $email_result['error']['code']
	) {
		$clearout_validation_result['status'] = false;
		$clearout_validation_result['reason'] = 'api_token';
		return $clearout_validation_result;
	}

	// something went wrong with validation, so always return valid email.
	$clearout_validation_result['status'] = true;
	$clearout_validation_result['reason'] = 'valid_email';

	if ( empty( $email_result ) || empty( $email_result['data'] ) ) {
		return $clearout_validation_result;
	}

	$whitelisted_codes = [ 
		CLEAROUT_VERIFICATION_EMAIL_WHITELISTED_SUBSTATUS_CODE,
		CLEAROUT_VERIFICATION_DOMAIN_WHITELISTED_SUBSTATUS_CODE,
		CLEAROUT_VERIFICATION_TLD_WHITELISTED_SUBSTATUS_CODE,
		CLEAROUT_VERIFICATION_ACCOUNT_WHITELISTED_SUBSTATUS_CODE
	];

	// Check for whitelisting of the emai/domain.
	if ( in_array( $email_result['data']['sub_status']['code'], $whitelisted_codes, true ) ) {
		return $clearout_validation_result;
	}

	// check the verification status of email address is invalid.
	if ( 'invalid' == $email_result['data']['status'] ) {
		$clearout_validation_result['status'] = false;
		$clearout_validation_result['reason'] = 'invalid_email';
		return $clearout_validation_result;
	}

	// does user checked safe to send email address as valid?
	if ( ( isset( $clearout_options['sts_on_off'] ) && 'on' == $clearout_options['sts_on_off'] ) ) {
		$is_sts = _co_is_sts( $email_result );
		if ( !$is_sts ) {
			$clearout_validation_result['status'] = false;
			$clearout_validation_result['reason'] = 'sts_email';
			return $clearout_validation_result;
		}
	}

	// check option filters.
	// does user checked only to accept business (non-free) email?
	if ( isset( $clearout_options['free_on_off'] ) && 'on' == $clearout_options['free_on_off'] ) {
		$is_free = _co_is_free( $email_result );
		if ( $is_free ) {
			$clearout_validation_result['status'] = false;
			$clearout_validation_result['reason'] = 'free_email';
			return $clearout_validation_result;
		}
	}
	// does user checked role based email address as  valid?
	if ( ! ( isset( $clearout_options['role_email_on_off'] ) && 'on' == $clearout_options['role_email_on_off'] ) ) {
		$is_role = _co_is_role_email( $email_result );
		if ( $is_role ) {
			$clearout_validation_result['status'] = false;
			$clearout_validation_result['reason'] = 'role_email';
			return $clearout_validation_result;
		}
	}

	// does user checked disposable email address as valid?
	if ( ! ( isset( $clearout_options['disposable_on_off'] ) && 'on' == $clearout_options['disposable_on_off'] ) ) {
		$is_disposable = _co_is_disposable( $email_result );
		if ( $is_disposable ) {
			$clearout_validation_result['status'] = false;
			$clearout_validation_result['reason'] = 'disposable_email';
			return $clearout_validation_result;
		}
	}

	// does user checked gibberish email address as valid?
	if ( ! ( isset( $clearout_options['gibberish_on_off'] ) && 'on' == $clearout_options['gibberish_on_off'] ) ) {
		$is_gibberish = _co_is_gibberish( $email_result );
		if ( $is_gibberish ) {
			$clearout_validation_result['status'] = false;
			$clearout_validation_result['reason'] = 'gibberish_email';
			return $clearout_validation_result;
		}
	}


	// Control comes here if no filters are selected i.e Only valid/INvalid email.
	return $clearout_validation_result;
}

/**
 * Method to get the error message
 *
 * @param mixed $error_status The error status object.
 */
function _get_error_message( $error_status ) {
	$error_message = 'This email address is invalid or not allowed - please check';
	switch ($error_status) {
		case 'api_token':
			$error_message = 'Invalid API Token, please check your API token';
			break;
		case 'invalid_email':
			$error_message = 'You have entered an invalid email address, Please try again with a valid email address';
			break;
		case 'disposable_email':
			$error_message = 'You have entered disposable email address, Please try again with non disposable email address';
			break;
		case 'free_email':
			$error_message = 'You have entered free service email address, Please try again with business / work email address';
			break;
		case 'role_email':
			$error_message = 'You have entered role-based email address, Please try again with non role-based email address';
			break;
		case 'gibberish_email':
			$error_message = 'You have entered a gibberish email address, please try again with a proper email';
			break;
		case 'sts_email':
			$error_message = 'Not a safe to send email address, please try with different email address';
			break;
		default:
			$error_message = 'This email address is not allowed due to ' . $error_status;
	}
	return $error_message;
}

/**
 * Method to EV filter.
 *
 * @param mixed $email the email.
 */
function clearout_email_validator_filter( $email ) {
	$is_valid_email = true;

	if ( empty( $email ) ) {
		return false;
	}

	if (
		( isset( $_SERVER['REQUEST_URI'] ) ) && ( ( '/wp-login.php' == $_SERVER['REQUEST_URI'] ) | ( '/wp-login.php?loggedout=true' == $_SERVER['REQUEST_URI'] ) | ( '/wp-cron.php' == $_SERVER['REQUEST_URI'] ) )
	) {
		// if wp-login.php is been called for login to dashboard, skip the check.
		return $is_valid_email;
	}

	if ( empty( function_exists( 'is_user_logged_in' ) ) ) {
		return $is_valid_email;
	}

	if ( is_user_logged_in() ) {
		$current_user = wp_get_current_user();
		$cruser_email = $current_user->user_email;
		if ( $email == $cruser_email ) {
			return $is_valid_email;
		}
	}

	// Get option settings to know which validator is been called.
	$clearout_options     = get_option( 'clearout_email_validator' );
	$clearout_form_source = 'custom';
	if ( ( ! ( '' == $clearout_options['api_key'] ) ) ) {
		// do the email validation.
		$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
		if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
			if ( false == $validation_result['status'] ) {
				$is_valid_email = false;
			}
		}
	}
	return $is_valid_email;
}


/**
 * Mailster EV Hook
 *
 * @param mixed $result Result object.
 */
function clearout_mailster_email_validator( $result ) {
	$clearout_form_source = 'mailsterform';

	if ( isset( $result['email'] ) ) {
		$email = $result['email'];

		// Get option settings to know which validator is been called.
		$clearout_options = get_option( 'clearout_email_validator' );
		$is_valid_email   = true;
		if ( ( '' == $clearout_options['api_key'] ) || ( '' == $email ) ) {
			return $result;
		}
		// do the email validation.
		$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
		if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
			if ( false == $validation_result['status'] ) {
				$is_valid_email = false;

				// To Support custom error mesage before going to switch case.
				if ( _check_custom_error_msg_exist( $clearout_options ) ) {
					return new WP_Error( 'email', $clearout_options['custom_invalid_error'] );
				}

				$error_message = _get_error_message( $validation_result['reason'] );
				return new WP_Error( 'email', $error_message );
			}
		}
	}

	return $result;
}

/**
 * Default WordPress Register Forms.
 *
 * @param mixed $errors Error object.
 * @param mixed $sanitized_user_login User Login.
 * @param mixed $email The email.
 */
function clearout_email_validator_wprg( $errors, $sanitized_user_login, $email ) {
	$clearout_form_source = 'wprg';

	if ( email_exists( $email ) ) {
		return $errors;
	}

	// Get option settings to know which validator is been called.
	$clearout_options = get_option( 'clearout_email_validator' );
	$is_valid_email   = true;
	if ( ( '' == $clearout_options['api_key'] ) || ( '' == $email ) ) {
		return $errors;
	}
	// do the email validation.
	$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
	if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
		if ( false == $validation_result['status'] ) {
			$is_valid_email = false;
			$errors->add( 'invalid_email', ( ( _check_custom_error_msg_exist( $clearout_options ) ) ? esc_html( $clearout_options['custom_invalid_error'] ) : esc_html__( 'This email address is invalid or not allowed - please check.', 'clearout-email-validator' ) ) );
			return $errors;
		}
	}
	return $errors;
}

/**
 * PmPro Register Forms.
 *
 * @param mixed $pmpro_continue_registration PmPro Object.
 */
function clearout_pmpro_signup_email_validate( $pmpro_continue_registration ) {

	if ( ! isset( $_POST['bemail'] ) ) {
		return false;
	}

	$email = sanitize_email( wp_unslash( ( $_POST['bemail'] ) ) );

	if ( empty( $email ) ) {
		return false;
	}

	// Get option settings to know which validator is been called.
	$clearout_options     = get_option( 'clearout_email_validator' );
	$clearout_form_source = 'pmpro';
	if ( ( ! ( '' == $clearout_options['api_key'] ) ) ) {
		// do the email validation.
		$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
		if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
			if ( false == $validation_result['status'] ) {
				$pmpro_continue_registration = false;
				if ( _check_custom_error_msg_exist( $clearout_options ) ) {
					pmpro_setMessage( esc_html( $clearout_options['custom_invalid_error'] ) );
				} else {
					$error_message = _get_error_message( $validation_result['reason'] );
					pmpro_setMessage( esc_html( $error_message ) );
				}
			}
		}
	}
	return $pmpro_continue_registration;
}

/**
 * Gravity Forms
 *
 * @param mixed $result Result object.
 * @param mixed $value Value.
 * @param mixed $form Form Object.
 * @param mixed $field Field Object.
 */
function clearout_gvf_email_validator( $result, $value, $form, $field ) {
	$clearout_form_source = 'gvf';

	if ( 'email' == $field->type && '0' == $field->isRequired && '' == $value ) {
		$result['is_valid'] = true;
		return $result;
	}
	if ( 'email' == $field->type && $result['is_valid'] ) {
		// Get option settings to know which validator is been called.
		$clearout_options = get_option( 'clearout_email_validator' );
		$is_valid_email   = true;
		if ( ( '' == $clearout_options['api_key'] ) && ( '' != $value ) ) {
			return $result;
		}
		// do the email validation.

		// Check if $value is array, because when user has double confirm email enabled,
		// $value comes as an array, causing our EV to fail
		$email = $value;
		if ( is_array( $value ) ) {
			$email = $value[0];
		}
		$sanitised_email   = sanitize_email( $email );
		$validation_result = _co_email_validation( $sanitised_email, $clearout_options, $clearout_form_source );
		if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
			if ( false == $validation_result['status'] ) {
				$is_valid_email     = false;
				$result['is_valid'] = false;
				if ( _check_custom_error_msg_exist( $clearout_options ) ) {
					$result['message'] = esc_html( $clearout_options['custom_invalid_error'] );
				} else {
					$error_message     = _get_error_message( $validation_result['reason'] );
					$result['message'] = esc_html( $error_message );
				}
				return $result;
			}
		}
	}

	return $result;
}

/**
 * Wp Forms.
 *
 * @param mixed $entry Entries.
 * @param mixed $form_data Form Data object.
 */
function clearout_wpf_email_validator( $entry, $form_data ) {
	$clearout_form_source = 'wpf';
	$hidden_ignore_fields = preg_grep( CLEAROUT_IGNORE_VALIDATION_IDENTIFIER_REGEX, $entry['fields'] );
	if ( count( $hidden_ignore_fields ) > 0 ) {
		return $form_data;
	}
	foreach ( $entry['fields'] as $key => $field ) {
		$value = $field;
		// ignore multi-line strings / textareas.
		if ( is_string( $value ) && preg_match( '/@.+\./', $value ) && strpos( $value, '\n' ) === false ) {
			$email = sanitize_email( $value );
			if ( empty( $email ) ) {
				$field_id = $field['id'];

				wpforms()->process->errors[ $form_data['id'] ]['header'] = esc_html__( 'This email address is invalid or not allowed - please check.', 'clearout-email-validator' );
				return $form_data;
			}

			// Get option settings to know which validator is been called.
			$clearout_options = get_option( 'clearout_email_validator' );
			if ( ( ! ( '' == $clearout_options['api_key'] ) ) && ( '' != $email ) ) {
				// do the email validation.
				$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
				if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
					if ( false == $validation_result['status'] ) {
						if ( _check_custom_error_msg_exist( $clearout_options ) ) {
							wpforms()->process->errors[ $form_data['id'] ]['header'] = esc_html( $clearout_options['custom_invalid_error'] );
							return;
						}
						$error_message = _get_error_message( $validation_result['reason'] );

						wpforms()->process->errors[ $form_data['id'] ]['header'] = esc_html( $error_message );
					}
				}
			}
		}
	}
}

/**
 * Ninja Forms.
 *
 * @param mixed $form_data Form Data.
 */
function clearout_ninja_email_validator( $form_data ) {
	$clearout_form_source = 'ninja';
	$hidden_ignore_fields = preg_grep( CLEAROUT_IGNORE_VALIDATION_IDENTIFIER_REGEX, array_column( $form_data['fields'], 'key' ) );
	if ( count( $hidden_ignore_fields ) > 0 ) {
		return $form_data;
	}

	foreach ( $form_data['fields'] as $key => $field ) {
		$value = $field['value'];
		// ignore multi-line strings / textareas.
		if ( is_string( $value ) && preg_match( '/@.+\./', $value ) && strpos( $value, '\n' ) === false ) {
			$email = sanitize_email( $value );
			if ( empty( $email ) ) {
				$field_id                                   = $field['id'];
				$form_data['errors']['fields'][ $field_id ] = esc_html__(
					'This email address is invalid or not allowed - please check.',
					'clearout-email-validator'
				);
				return $form_data;
			}

			// Get option settings to know which validator is been called.
			$clearout_options = get_option( 'clearout_email_validator' );
			if ( ( ! ( '' == $clearout_options['api_key'] ) ) && ( '' != $value ) ) {
				// do the email validation.
				$validation_result = _co_email_validation( $value, $clearout_options, $clearout_form_source );
				if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
					if ( false == $validation_result['status'] ) {
						$field_id = $field['id'];
						if ( _check_custom_error_msg_exist( $clearout_options ) ) {
							$form_data['errors']['fields'][ $field_id ] = esc_html( $clearout_options['custom_invalid_error'] );
						} else {
							$error_message                              = _get_error_message( $validation_result['reason'] );
							$form_data['errors']['fields'][ $field_id ] = esc_html( $error_message );
						}

						return $form_data;
					} else {
						return $form_data;
					}
				} else {
					return $form_data;
				}
			} else {
				// If the user do not enter the API Token, or ignore the admin notice, or the $email is empty, just let it pass.
				return $form_data;
			}
		}
	}
	return $form_data;
}

/**
 * Contact Form 7.
 *
 * @param mixed $result Result Object.
 * @param mixed $tags Tags Object.
 */
function clearout_wpcf7_custom_email_validator_filter( $result, $tags ) {
	$clearout_form_source = 'contactform7';

	// Get option settings to know which validator is been called.
	$clearout_options = get_option( 'clearout_email_validator' );
	$tags             = new WPCF7_FormTag( $tags );
	$type             = $tags->type;
	$name             = $tags->name;

	// Chec if post Nmame present.
	if ( ! isset( $_POST[ $name ] ) ) {
		return $result;
	}

	$email = sanitize_email( wp_unslash( $_POST[ $name ] ) );

	if ( ( '' == $clearout_options['api_key'] ) || ( '' == $email ) ) {
		return $result;
	}
	if ( empty( $email ) && 'email*' == $type ) {
		$result->invalidate(
			$tags,
			esc_html__(
				'You have entered an invalid email address, Please try again with a valid email address',
				'clearout-email-validator'
			)
		);
		return $result;
	}
	$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
	if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
		if ( false == $validation_result['status'] ) {
			if ( _check_custom_error_msg_exist( $clearout_options ) ) {
				$result->invalidate( $tags, esc_html( $clearout_options['custom_invalid_error'] ) );
				return $result;
			}
			$error_message = _get_error_message( $validation_result['reason'] );
			$result->invalidate( $tags, esc_html( $error_message ) );
		}
	}
	return $result;
}

/**
 * Formidable Forms.
 *
 * @param mixed $errors Errors.
 * @param mixed $values Values.
 */
function clearout_frm_validate_entry( $errors, $values ) {
	foreach ( $values['item_meta'] as $key => $value ) {
		if ( gettype( $value ) != 'string' ) {
			continue;
		}
		if ( preg_match( CLEAROUT_IGNORE_VALIDATION_IDENTIFIER_REGEX, $value ) ) {
			return $errors;
		}
	}

	$clearout_form_source = 'formidable';
	foreach ( $values['item_meta'] as $key => $value ) {
		if ( is_string( $value ) && preg_match( '/^\S+@\S+\.\S+$/', $value ) ) {
			$clearout_options = get_option( 'clearout_email_validator' );
			$email            = sanitize_email( $value );

			if ( empty( $email ) ) {
				$errors['ct_error'] = esc_html__(
					'You have entered an invalid email address, Please try again with a valid email address',
					'clearout-email-validator'
				);
				return $errors;
			}

			if ( ( '' != $clearout_options['api_key'] ) && ( '' != $email ) ) {
				$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
				if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
					if ( false == $validation_result['status'] ) {
						if ( _check_custom_error_msg_exist( $clearout_options ) ) {
							$errors['ct_error'] = esc_html( $clearout_options['custom_invalid_error'] );
							return $errors;
						}
						$error_message      = _get_error_message( $validation_result['reason'] );
						$errors['ct_error'] = esc_html( $error_message );
					}
				}
			}
		}
	}
	return $errors;
}

/**
 * BwS Forms.
 */
function clearout_bws_validate_email() {
	global $cntctfrm_error_message;
	$clearout_form_source = 'bestwebsoft';
	if ( ! ( empty( $_POST['cntctfrm_contact_email'] ) ) && ( '' != $_POST['cntctfrm_contact_email'] ) ) {
		$clearout_options = get_option( 'clearout_email_validator' );
		$email            = sanitize_email( wp_unslash( $_POST['cntctfrm_contact_email'] ) );

		if ( empty( $email ) ) {
			$cntctfrm_error_message['error_email'] = esc_html__(
				'You have entered an invalid email address, Please try again with a valid email address',
				'clearout-email-validator'
			);
			return;
		}

		if ( ( '' != $clearout_options['api_key'] ) && ( '' != $email ) ) {
			$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
			if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
				if ( false == $validation_result['status'] ) {
					if ( _check_custom_error_msg_exist( $clearout_options ) ) {
						$cntctfrm_error_message['error_email'] = esc_html( $clearout_options['custom_invalid_error'] );
						return;
					}
					$error_message                         = _get_error_message( $validation_result['reason'] );
					$cntctfrm_error_message['error_email'] = esc_html( $error_message );
				}
			}
		}
	}
}

/**
 * Woocommerce Checkout Forms.
 *
 * @param mixed $fields Fields Object.
 * @param mixed $errors Errors Object.
 */
function clearout_woocom_checkout_validate_email( $fields, $errors ) {
	$clearout_form_source = 'woochkfrm';

	if ( isset( $fields['billing_email'] ) ) {
		$email = $fields['billing_email'];

		// Get option settings to know which validator is been called.
		$clearout_options = get_option( 'clearout_email_validator' );
		$is_valid_email   = true;
		if ( ( ! ( '' == $clearout_options['api_key'] ) ) && ( '' != $email ) ) {
			// do the email validation.
			$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
			if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
				if ( false == $validation_result['status'] ) {
					$is_valid_email = false;
					// if any validation errors.
					// remove all of them.
					foreach ( $errors->get_error_codes() as $code ) {
						$errors->remove( $code );
					}

					if ( _check_custom_error_msg_exist( $clearout_options ) ) {
						$errors->add( 'validation', $clearout_options['custom_invalid_error'] );
						return;
					}
					$error_message = _get_error_message( $validation_result['reason'] );
					$errors->add( 'validation', $error_message );
				}
			}
		}
	}
}

/**
 * Elementor Forms
 *
 * @param mixed $field Field Object.
 * @param mixed $record Records Object.
 * @param mixed $ajax_handler The Ajax handler.
 */
function clearout_elementor_email_validator( $field, $record, $ajax_handler ) {
	$clearout_form_source = 'elementor';

	if ( preg_match( CLEAROUT_IGNORE_VALIDATION_IDENTIFIER_REGEX, $field['id'] ) ) {
		return;
	}
	if ( empty( $field['value'] ) ) {
		$ajax_handler->add_error( $field['id'], 'You have entered an invalid email address, Please try again with a valid email address' );
		return;
	}

	// Get option settings to know which validator is been called.
	$clearout_options = get_option( 'clearout_email_validator' );
	if ( ! ( '' == $clearout_options['api_key'] ) ) {
		// Email Validation.
		$validation_result = _co_email_validation( $field['value'], $clearout_options, $clearout_form_source );
		if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
			if ( false == $validation_result['status'] ) {
				if ( _check_custom_error_msg_exist( $clearout_options ) ) {
					$ajax_handler->add_error( $field['id'], $clearout_options['custom_invalid_error'] );
					return;
				}
				$error_message = _get_error_message( $validation_result['reason'] );
				$ajax_handler->add_error( $field['id'], $error_message );
			}
		}
	}
}

/**
 * Fluent Forms.
 *
 * @param mixed $error_message Error message object.
 * @param mixed $field Field.
 * @param mixed $form_data Form Data Obejct.
 * @param mixed $fields Fields Object.
 * @param mixed $form Form Object.
 */
function clearout_fluent_email_validator( $error_message, $field, $form_data, $fields, $form ) {
	$clearout_form_source = 'fluent';

	if ( isset( $form_data['email'] ) ) {
		$email = $form_data['email'];
		// Get option settings to know which validator is been called.
		$clearout_options = get_option( 'clearout_email_validator' );
		$is_valid_email   = true;
		if ( ( ! ( '' == $clearout_options['api_key'] ) ) && ( '' != $email ) ) {
			// do the email validation.
			$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
			if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
				if ( false == $validation_result['status'] ) {
					$is_valid_email = false;
					if ( _check_custom_error_msg_exist( $clearout_options ) ) {
						$error_message = [ $clearout_options['custom_invalid_error'] ];
					} else {
						$error_message = [ _get_error_message( $validation_result['reason'] ) ];
					}
				}
			}
		}
	}
	return $error_message;
}

/**
 * WS Forms.
 *
 * @param mixed $valid Is Email valid or not.
 * @param mixed $email Email Value.
 */
function clearout_wsf_email_validator( $valid, $email ) {
	$clearout_form_source = 'wsf';

	// Empty email check, in case user doesnt prevent empty submission in form.
	if ( empty( $email ) ) {
		return esc_html__( 'Email field is empty' );
	}
	// Get option settings to know which validator is been called.
	$clearout_options = get_option( 'clearout_email_validator' );
	$is_valid_email   = true;
	if ( ( ! ( '' == $clearout_options['api_key'] ) ) && ( '' != $email ) ) {
		// do the email validation.
		$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
		if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
			if ( false == $validation_result['status'] ) {
				$is_valid_email = false;
				if ( _check_custom_error_msg_exist( $clearout_options ) ) {
					$error_message = $clearout_options['custom_invalid_error'];
				} else {
					$error_message = _get_error_message( $validation_result['reason'] );
				}
			}
		}
	}
	return $is_valid_email ? $is_valid_email : esc_html( $error_message );
}

/**
 * Forminator Forms.
 *
 * @param mixed $submit_errors Submit Error object.
 * @param mixed $form_id Form id.
 * @param mixed $field_data_array Field Data Array.
 */
function clearout_forminator_email_validator( $submit_errors, $form_id, $field_data_array ) {
	$clearout_form_source = 'forminator';
	$email                = null;

	foreach ( $field_data_array as $val ) {
		// For hidden field skip validation support.
		if ( 'hidden-1' == $val['name'] ) {
			if ( preg_match( CLEAROUT_IGNORE_VALIDATION_IDENTIFIER_REGEX, $val['value'] ) ) {
				return $submit_errors;
			}
		}
		if ( 'email-1' == $val['name'] ) {
			$email = $val['value'];
		}
	}

	// Empty email check, in case user doesnt prevent empty submission in form.
	if ( empty( $email ) ) {
		return esc_html__( 'Email field is empty' );
	}
	// Get option settings to know which validator is been called.
	$clearout_options = get_option( 'clearout_email_validator' );
	$is_valid_email   = true;
	if ( ( ! ( '' == $clearout_options['api_key'] ) ) && ( '' != $email ) ) {
		// do the email validation.
		$validation_result = _co_email_validation( $email, $clearout_options, $clearout_form_source );
		if ( ( is_array( $validation_result ) ) && array_key_exists( 'status', $validation_result ) ) {
			if ( false == $validation_result['status'] ) {
				$is_valid_email = false;
				if ( _check_custom_error_msg_exist( $clearout_options ) ) {
					$submit_errors[]['email-1'] = $clearout_options['custom_invalid_error'];
				} else {
					$submit_errors[]['email-1'] = _get_error_message( $validation_result['reason'] );
				}
			}
		}
	}
	return $submit_errors;
}
