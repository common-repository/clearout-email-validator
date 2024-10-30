const CLEAROUT_CONSTANTS = {
	CLEAROUT_ADMIN_OPTIONS_PAGE_SLUG: 'page=clearout-email-validator'
}

jQuery(document).ready(function () {
	// AmsifySuggestags TO implement the Tags for the Filter URLS
	if (window.location.href.indexOf(CLEAROUT_CONSTANTS.CLEAROUT_ADMIN_OPTIONS_PAGE_SLUG) > -1) {
		const filterUrlTags = new AmsifySuggestags(jQuery('#filter_urls'));
		filterUrlTags._settings({
			tagLimit: 50,
			printValues: false,
			afterAdd: function (url) {
				// validate if its a URL
				try {
					let urlObj = new URL(url)
					// Only save the origin + pathname, and remoev any query params
					let sanitisedUrl = urlObj.origin + urlObj.pathname

					// if it ends with slash, remove it and save it, to maintain uniqueness
					if (sanitisedUrl.endsWith('/')) sanitisedUrl = sanitisedUrl.slice(0, -1)

					// If the sanitised URL is diff, remoe that from the tags and add this instead
					if (sanitisedUrl !== url) {
						filterUrlTags.removeTag(url)
						filterUrlTags.addTag(sanitisedUrl)
					}
				} catch (e) {
					filterUrlTags.removeTag(url)
				}
			}
		})
		filterUrlTags._init()

		const excludeFilterUrlTags = new AmsifySuggestags(jQuery('#exclusion_filter_urls'));
		excludeFilterUrlTags._settings({
			tagLimit: 50,
			printValues: false,
			afterAdd: function (url) {
				// validate if its a URL
				try {
					let urlObj = new URL(url)
					// Only save the origin + pathname, and remoev any query params
					let sanitisedUrl = urlObj.origin + urlObj.pathname

					// if it ends with slash, remove it and save it, to maintain uniqueness
					if (sanitisedUrl.endsWith('/')) sanitisedUrl = sanitisedUrl.slice(0, -1)

					// If the sanitised URL is diff, remoe that from the tags and add this instead
					if (sanitisedUrl !== url) {
						excludeFilterUrlTags.removeTag(url)
						excludeFilterUrlTags.addTag(sanitisedUrl)
					}
				} catch (e) {
					excludeFilterUrlTags.removeTag(url)
				}
			}
		})
		excludeFilterUrlTags._init()
	}


	jQuery('body').on('click', '#clearout_email_address_submit', function (e) {
		e.preventDefault();

		if (e.handled !== true) { // This will prevent event triggering more then once
			event.handled = true;
		} else {
			// to handle multiple callback
			return
		}

		if (!jQuery('#clearout_email_address_input').val()) {
			return
		}

		if (jQuery('#clearout_email_address_input').val().length > 320) {
			jQuery("#clearout_result_div").html("<p style='font-size:14px;display: flex;align-items: center;'><i class='fa fa-times-circle' style='font-size:20px;color:red;'></i>&nbsp;&nbsp;Invalid - Email address length exceed 320 characters </p>");
			return
		}
		jQuery("#clearout_validate_button_div").html("<button id='clearout_email_address_submit' class='button button-primary'><i class='fa fa-spinner fa-spin'></i>&nbsp;&nbsp;Validating...</button>");
		// console.log('See the sanitize data',sanitize_email(jQuery('#clearout_email_address_input').val()))
		jQuery.ajax({
			url: clearout_plugin_ajax_call.ajax_url,
			type: 'post',
			data: {
				action: 'co_test_plugin_setting_action',
				clearout_email: jQuery('#clearout_email_address_input').val(),
				clearout_timeout: jQuery('#timeout').val() * 1000,
				_wpnonce: clearout_plugin_ajax_call.nonce
			},
			success: function (response /** raw response object */) {
				jQuery("#clearout_validate_button_div").html("<input id='clearout_email_address_submit' name='Submit' type='submit' value='Test' class='button button-primary'/>");
				if (response && response.status === 'success') {
					// response = JSON.parse(response.body);
					// jQuery('.clearout_email_address_input').html(response);
					if (response.data.status === false) { //invald email
						jQuery("#clearout_result_div").html("<p style='font-size:14px;display: flex;align-items: center;'><i class='fa fa-times-circle' style='font-size:20px;color:red;'></i>&nbsp;&nbsp;Invalid - " + response.data.reason + "</p>");
					} else {
						jQuery("#clearout_result_div").html("<p style='font-size:14px;display: flex;align-items: center;'><i class='fa fa-check-circle' style='font-size:20px;color:green;'></i>&nbsp;&nbsp;" + response.data.reason + "</p>");
					}
				} else {
					jQuery("#clearout_result_div").html("<p style='font-size:14px;display: flex;align-items: center;'><i class='fa fa-times-circle' style='font-size:20px;color:red;'></i>&nbsp;&nbsp;Something went wrong please contact us@clearout.io</p>");
				}
			},
			error: function (request, status, error) {
				let errors = JSON.parse(request.responseText);
				//jQuery('#result_email_valid').text(errors.error.message);
				jQuery("#clearout_result_div").html("<p style='font-size:14px;display: flex;align-items: center;'><i class='fa fa-times-circle' style='font-size:20px;color:red;'></i>&nbsp;&nbsp;" + errors.error.message + "</p>");

			}
		});
	});

	function toggleCheckboxes() {
		if (jQuery('#sts_option').is(':checked')) {
			jQuery('#role_email_option, #disposable_option, #gibberish_option').prop('disabled', true);
		} else {
			jQuery('#role_email_option, #disposable_option, #gibberish_option').prop('disabled', false);
		}
	}

	// Run on page load
	toggleCheckboxes();

	// Run on change
	jQuery('#sts_option').change(function () {
		toggleCheckboxes();
	});

	// Show tooltip on mouse over for disabled checkboxes
	jQuery('.cleraout-input-box-tooltip input[type="checkbox"]').hover(function () {
		if (jQuery(this).is(':disabled')) {
			jQuery(this).siblings('.cleraout-tooltiptext').css('visibility', 'visible').css('opacity', '1');
		}
	}, function () {
		jQuery(this).siblings('.cleraout-tooltiptext').css('visibility', 'hidden').css('opacity', '0');
	});

});
