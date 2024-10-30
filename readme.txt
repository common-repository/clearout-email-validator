=== Clearout Email Validator - Real-Time Email Verification on WordPress Forms ===
Contributors: clearoutio
Donate link: https://Clearout.io
Tags: email verifier, email checker, email verification, email validation, woocommerce
Requires at least: 4.6
Tested up to: 6.5.5
Stable tag: 3.1.5
License: GPLv2 or later
Block invalid emails like temporary, disposable, etc. with our real-time email verification. Verify email address during form-fill and stop form spam.

== Description ==

Clearout Email Validation plugin seamlessly integrates with all major forms to validate the email addresses in real time.

The plugin performs 20+ refined real-time validation checks to determine the current status of the email address. These checks include extensive verifications like greylist verification, anti-spam check, gibberish check, catch-all verification, email blacklist verification, temporary email address check, and more.


= Key Benefits of Using Clearout Email Verification Plugin: =
* Accept only <strong>safe-to-send</strong> email address to <strong>protect your sender reputation</strong>
* Accept only <strong>business or work email addresses</strong>
* <strong>Prevent fraudulent signups or leads getting into CRM</strong> by stopping [temporary / disposable / throw away email addresses](https://clearout.io/blog/2020/09/30/dont-let-your-email-campaigns-be-a-victim-of-disposable-email-addresses)
* <strong>Customization to Block free email address providers</strong> like gmail.com / yahoo.com / hotmail.com
* <strong>Remove</strong> duplicate and <strong>alias email addresses</strong>

= How to Install Clearout Email Verifier Plugin =

<strong>Obtain an API Token:</strong>
1. <strong>Log in</strong> to your Clearout account.
2. Navigate to the [‘Apps’](https://app.clearout.io/apps/list) menu and click on <strong>‘+ Create App’</strong>.
3. Select <strong>‘Server’</strong>, add the necessary details for reference, and click on “Create” to generate the API token.

<strong>Create a Clearout Account (if you don't have one):</strong>
1. [Sign up](https://app.clearout.io/register) for a Clearout account to <strong>get 100 free email validation credits with no credit card required</strong>.

For more detailed instructions, visit Clearout [Email Verifier Plugin Installation](https://clearout.io/integrations/wordpress/).

https://youtu.be/YG5BrBn7FHo


= Supported Forms/Plugins =
The Clearout email verification plugin supports a rich set of popular form-based plugins by listening to email address capture flow or by hooking into WordPress is_email() function:

* Elementor Form
* Gravity Forms
* Forminator Form
* WooCommerce 
* Fluent Form
* WP Forms
* Formidable forms
* WS Form 
* WP-Members
* Contact Form
* Mailster Form
* MailChimp
* Ninja Forms
* Profile Builder
* Ultimate Member registration form
* Users Ultra registration form
* JetPack comments and a contact form
* MailPoet
* Theme My Login
* Paid Memberships Pro
* Form Maker by 10Web
* Visual Form Builder
* Any WordPress registrations & contact forms   


= Key Features =

* Accurate Email Verification
* Fastest Real-time Email Validation
* Seamless API Integration
* Guaranteed Deliverability (Safe to send)
* High Precision Advanced Catch-all Resolver
* Block Role Email
* Block Disposable Email
* Block Gibberish Email
* Email / Domain Allowlisting and Blocklisting
* Custom Error Message
* Limit email validation to only required pages
* Low Credit Notification Alert
* Team Accounts
* Syntax Verification
* [Test email addresses](https://docs.clearout.io/api-overview.html#testing)

= Know A Little More About Clearout Email Verification Service =
In addition to its availability as a WordPress Plugin, Clearout Email Verifier supports email verification in multiple forms and ways to meet the needs of the user. Other verification methods supported by Clearout Email Verifier are - Bulk email list validation, real-time email validation API, and Javascript Email Validation. 

= FURTHER READING =
More about Clearout Email Verification

* [https://clearout.io/email-verification-api/](https://clearout.io/email-verification-api/)
* [https://clearout.io/disposable-email-checker/](https://clearout.io/disposable-email-checker/)
* [https://clearout.io/integrations/](https://clearout.io/integrations/)
* [https://clearout.io/help/](https://clearout.io/help/)
* [https://docs.clearout.io/](https://docs.clearout.io/)

Other Clearout Services

* [https://clearout.io/email-finder/](https://clearout.io/email-finder/)
* [https://clearout.io/sales-prospecting/chrome-extension/](https://clearout.io/sales-prospecting/chrome-extension/)
* [https://clearout.io/sales-prospecting/advanced-data-enrichment/](https://clearout.io/sales-prospecting/advanced-data-enrichment/)
* [https://clearout.io/reverse-lookup/linkedin/](https://clearout.io/reverse-lookup/linkedin/)
* [https://clearout.io/reverse-lookup/email/](https://clearout.io/reverse-lookup/email/)

== Installation ==

### Installation using WordPress dashboard

1. Select <strong>Plugins -> Add New</strong>.
2. Search for <strong>"Clearout Email Validator"</strong>.
3. Click on <strong>Install Now</strong> to install the plugin.
4. Click on <strong>Activate</strong> button to activate the plugin.
5. Get your [Clearout API token](https://app.clearout.io/apps/list) before start using the plugin.
6. Configure the plugin settings, including your API key, and check/uncheck the role, disposable, and Business email validator.

### Manual Installation

1. Upload the plugin files to the `/wp-content/plugins/clearout-email-validator` directory.
2. Activate the plugin through the <strong>Plugins</strong> screen in WordPress
3. Get your Clearout API token through [here](https://app.clearout.io/apps/list).
4. Configure the plugin settings, including your API key, and switch on or off the valid, disposable, and free email validator.

== Frequently Asked Questions ==

= What is real-time email verification? =

Real-time email verification refers to the process of confirming the authenticity or existence of an email address account in real time. Its results are based on real-time analysis rather than on basic checks against the old & existing databases.

= How does this plugin work?  =

This Email Validation plugin listens to email address capture flow for all major forms by hooking WordPress is_email() function to verify whether the user's typed email address can be accepted or not. Behind the screen, the verification will be carried out using Clearout API and the results will be matched with the appropriate settings allowed by the plugin.

= Which Clearout status will be considered as a “valid” email address?  =

Clearout status other than “invalid” will be considered as “valid” email address and the form submission will be allowed. Also, by default, the email address of “disposable” or “role” will be considered as “invalid.” These settings can be changed in the plugin settings.

= Does email validation stop all bad emails? =
    No, Clearout email validation cannot prevent bad emails from entering your system in the following conditions:
    1. If email validation takes longer than the specified timeout value
    2. If the status of email validation is returned as unknown

= What version of WordPress is required? =

This requires a minimum WordPress version of 4.6, tested and compatible with the latest version.

= Why does "Select Forms" have only a few forms listed? =

We strive to bring Clearout email validation support to all major WordPress forms, in case if you see your form is not listed let us know (us@clearout.io). Alternatively, you can try using [Clearout JavaScript Widget](https://docs.clearout.io/jswidget.html) to bring support of email validation to any form with little or no coding effort

= What is an API token and where can I get it? =

The API token is a unique representation of your access to Clearout Email Validation Service.
The API token can be created or obtained by creating a 'Server' App from the Apps menu.

= How to generate an API token? =

Once logged in to your Clearout account click on 'Apps'–> Click on '+ Create App'–> Choose 'Server'-> Provide the required details –> Click on Create and the API token will be generated.

= What is a credit? =

A credit represents the successful validation of a single email address. The trial account comes with 100 FREE credits. Additional credits can be purchased anytime and the credits will never expire.

= Do you provide test email address? =

Yes. For testing, you can find [test email addresses](https://docs.clearout.io/api-overview.html#testing) to confirm that your integration works as intended without incurring credits.

= What happens once the 100 free credits are exhausted? =

You need to purchase additional credits. System will notify in advance when you are [running out of credits](https://app.clearout.io/settings/notifications) (by default when below 50 credits) 

= What factors determine the high accuracy level claimed by Clearout email validation plugin? =

Clearout WordPress Plugin performs more than 20+ validation checks on each email address to provide 99% accuracy level. These rigorous validation checks have a wide scale ranging from role/free account check to disposable email verification, spam trap detection, email blacklist verification, gibberish check  & a lot more.

= How secure is my data? = 

Clearout email verifier is GDPR compliant. Data is highly secure since we take security and confidentiality seriously. At default, your processed data is retained in our system for 30 days, and it can be erased immediately if requested. In addition, all financial information is encrypted and maintained in a military-grade secure system.

= How long will it take to validate an email address? =

Clearout email verifier has been rewarded to have the fastest TAT(Turnaround Time ). Some domains might take longer time than expected. But free domains like gmail.com are verified in less than a half-a-second (less than 100 milliseconds)

=  How to buy more credits? =

Buy the desired number of email verifier credits in a few clicks by clicking on [Buy Credits](https://app.clearout.io/account/pricing) from your account.

= How to opt out of the Clearout Email checker on a specific form? =

Clearout Email checker is enabled by default on all forms on the website. If it is necessary to skip validation on a given form, it must be handled as mentioned below.

- Ninja Forms
    1. Ensure to enable [Developer mode](https://ninjaforms.com/docs/developer-mode/) for your ninja form builder
    2. Open the form in the Form editor that does not require the Clearout Email Validation
    3. Open the Email field setting and under the ADMINISTRATION option enter the key value prefixed with 'clearout_skip_validation' for the field key and save the changes
   
- Formidable / WP Form
    1. Open the form in the Form editor that does not require the Clearout Email Validation
    2. Add a new hidden field and in Options Advanced settings, enter the default value prefixed with 'clearout_skip_validation' and save the changes.

- Elementor forms
    1. Open the form in the Form editor that does not require the Clearout Email Validation
    2. In the Fields's Advanced settings, enter the ID value prefixed with 'clearout_skip_validation' and save the changes.

- Forminator forms
    1. Open the form in the Form editor that does not require the Clearout Email Validation
    2. Add a new hidden field and enter the value as ‘clearout_skip_validation’ and save the changes.

= Do you support page or form-specific custom validation? =

Yes, add the page URL that hosts the form in the 'Add Form Page URLs' to limit validation to page-specific or to limit form-specific custom validation through [Clearout JavaScript Widget](https://docs.clearout.io/jswidget.html), the integration is simple and can be done without need of developer help. Clearout JS widget provides all the bells and whistles to customize the email validation as per your need.    

= Looking for custom integration of this plugin? =

Send us an email at us@clearout.io or say "Hello" in the chat

= Where can I report bugs?    =

Send us an email at us@clearout.io or say "Hello" in the chat

== Screenshots ==

1. Clearout Email Validator setting page. Here you can add your Clearout API token and check/uncheck the role, disposable and Business email validator options.
2. Example - BWS Form denying free service email address.
3. Example - BWS Form denying invalid email addresses with a custom error message.
4. Example - BWS Form denying invalid email address.
5. Example - BWS Form denying invalid email addresses with a custom error message.
6. Example - Clearout Account page to generate API token. 

== Changelog ==

= 1.0.0 =
* Initial Release
= 1.0.1 =
* Content and Banner Changed
= 1.0.2 =
* Description Changed
= 1.1.0 =
* Major Bug Fixes and performance increased
= 1.1.1 =
* Major Bug Fixes and Performance Improvement
= 1.1.2 =
* Minor Bug Fixes
= 1.1.3 =
* Minor Bug Fixes
= 1.1.4 =
* Performance Improvements.
= 1.1.5 =
* Performance Improvements.
= 1.1.6 =
* WPForm incompatible Fixes
= 1.1.7 =
* Minor Bug Fixes
= 1.1.8 =
* Bug Fixes
= 1.2.0 =
* Performance Improvements & Bug Fixes
= 1.3.0 =
* UI and Particular forms select changes
= 1.3.1 =
* Added Support for Mailster Form and WooCommerce Checkout form
= 1.3.2 =
* Minor Changes
= 1.3.3 =
* Performance Improvements
= 1.3.4 =
* Minor Changes
= 1.4.0 =
* Support PM Pro form
= 1.5.0 =
* Support Elementor form
= 1.5.1 =
* Minor Changes
= 1.5.2 =
* Minor Changes
= 1.5.3 =
* Minor Changes
= 1.6.0 =
* Added Support for Fluent Form
= 1.6.1 =
* Minor Changes
= 1.6.2 =
* Minor Changes
= 1.6.3 =
* Minor Changes
= 1.6.4 =
* Supported WordPress version 5.7.2
= 1.6.5 =
* Warning fix
* Added Gibberish support
= 1.6.6 =
* Minor Changes
= 1.7.0 =
* Added support for WS Forms
= 1.7.1 =
* Minor Changes
= 1.7.2 =
* Minor Fixes
= 1.7.3 =
* Minor Bug Fixes
= 1.7.4 =
* Minor Enhancements
= 1.7.5 =
* Custom Invalid Error Message
= 1.7.6 =
* Minor Changes
= 1.7.7 =
* Minor Fixes
= 1.7.8 =
* Minor Optimisations
= 1.7.9 =
* Minor Fixes
= 1.7.10 =
* Minor Improvements
= 1.7.11 =
* Support of form specific validation
= 1.7.12 =
* Minor Fixes
= 2.0.0 =
* Major Fixes and Woocommerce form improvements
= 2.0.1 =
* Minor Fixes
= 2.0.2 =
* Minor Fixes and updated Readme
= 2.0.3 =
* Minor Fixes and error handling
= 2.0.4 =
* Minor Fixes and added strict mode
= 2.1.0 =
* Added Support for Forminator Forms and Filter Urls
= 2.1.1 =
* Optimised and improved Filter Urls
= 3.0.0 =
* Security Fixes and Code Optimisations
= 3.0.1 =
* Minor Fixes
= 3.0.2 =
* Minor Fixes
= 3.0.3 =
* Gravity Form Fixes
= 3.0.4 =
* By default, is_email option is disabled
= 3.1.0 =
* Exclusion URL Support
= 3.1.1 =
* Minor Fixes
= 3.1.2 =
* Compatibility Fixes
= 3.1.3 =
* Inclusion & Exclusion url improvements
= 3.1.4 =
* Minor Changes
= 3.1.5 =
* Minor Optimizations
* Added safe to send option
