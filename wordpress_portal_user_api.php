<?php

// PORTAL API GLOBAL ENVIRONMENT VARIABLES

	// Restricted Portal Pages URL Slugs

	global $restricted_pages;
	$restricted_pages = [
		'forge-resource-center-additional-links',
		'forge-resource-center-green-screen',
		'forge-resource-center-home',
		'forge-resource-center-live-events',
		'forge-resource-center-monthly-marketing',
		'forge-resource-center-radio',
		'forge-resource-center-television'
	];

	// MySql Portal Users Table Name

	global $wpdb;
	global $portal_table_name;
	$portal_table_name = $wpdb->prefix . "portal_users";

	// Select Portal Users Query

	global $select_portal_users;
	$select_portal_users = "SELECT * FROM ". $portal_table_name;

	// MySql Portal Admin Users Table Name

	global $admin_table_name;
	$admin_table_name = $wpdb->prefix . "users";

	// Select Portal Admins Query

	global $select_portal_admins;
	$select_portal_admins = "SELECT * FROM ". $admin_table_name;

	// Portal Uses/Admin Logged In Cookie Names

	global $admin_cookie_name;
	$admin_cookie_name = "portal_admin";
	global $user_cookie_name;
	$user_cookie_name = "portal_user";

	global $admin_cookie;
	$admin_cookie = $_COOKIE[$admin_cookie_name];
	global $user_cookie;
	$user_cookie = $_COOKIE[$user_cookie_name];

	// Portal User Login Page URL

	global $portal_login_url;
	$portal_login_url = 'https://www.partnerwithmagellan.com/portal-user-login/';

	// Portal Homepage URL For Logged In Users

	global $portal_home_url;
	$portal_home_url = 'https://www.partnerwithmagellan.com/forge-resource-center-home/';

	// Portal Cookie Expiration Time In Days

	global $cookie_days_remember;
	$cookie_days_remember = 7;

	global $cookie_not_remembered;
	$cookie_not_remembered = 1;

	// Portal User Cookie Key

	global $portal_user_key;
	$portal_user_key = '4&c!0)b2x$-~["h3Nz|*qX?$_;6^`UO}.t!';

	// Portal Admin Cookie Key

	global $portal_admin_key;
	$portal_admin_key = '-@8X-11-%^Z-B@Z*-6125-V&tZ-2185-+cz@-4';

	// Portal User Password Salt 
	
	global $portal_password_salt;
	$portal_password_salt = '0!dB%z_@Ga,IxQ8#s=P{@?~|fX$*v2V]oF&x';

// PAGE ACCESS RESTRICTIONS

	// Allows Access To Portal Pages Only If Portal User Or Portal Admin Cookie Present. If Not, Redirected To Portal User Login
	
	add_action('template_redirect', function() {

		// Portal Page URL Slugs That Will Be Restricted To Portal Users And Portal Admins Only

		global $restricted_pages;

		// Portal User Login Page URL

		global $portal_login_url;
		
		foreach($restricted_pages as $page) {
			if (is_page($page)) {
				if (!verify_portal_cookie('admin') && !verify_portal_cookie('user') && !is_user_logged_in()) {
					wp_redirect($portal_login_url); 
					exit();
				}
			}
		}
		
		// Redirect From Login To Portal Home Page If Portal User Or Admin Cookie Found
		
		// Portal User Logged In Homepage URL

		global $portal_home_url;

		if (is_page('portal-user-login')) {
			if (verify_portal_cookie('admin') || verify_portal_cookie('user')) {
				if (!isset($_COOKIE["wordpress_test_cookie"])) {
					wp_redirect($portal_home_url); 
					exit();
				}
			}
		}
	});

// COOKIES

	// Generate Portal Admin/User Cookie

	function generate_portal_cookie($id, $is_admin, $remember, $created) {

		$days_to_cookie_expiration_calc = time(); 

		// Number Of Days Until Cookie Expires Date Encoding

		global $cookie_days_remember;

		global $cookie_not_remembered;

		if ($remember) {
			$days_till_calc = $cookie_days_remember * 86400;
			$days_to_cookie_expiration_calc = time() + $days_till_calc;
		} else {
			$days_till_calc = $cookie_not_remembered * 86400;
			$days_to_cookie_expiration_calc = time() + $days_till_calc;
		}

		// Cookie Keys For Security

		global $portal_user_key;
		global $portal_admin_key;

		// Signature Is Encoded With Created Date, Key, And Expiration Concatenated Together Before Hashing

		$encoded = base64_encode(json_encode([
			'id' => $id,
			'expiration' => $days_to_cookie_expiration_calc,
			'type' => $is_admin ? 'admin' : 'user',
			'signature' => $is_admin ? wp_hash_password(base64_encode(strval($created)) . $portal_admin_key . base64_encode(strval($days_to_cookie_expiration_calc))) 
				: wp_hash_password(base64_encode(strval($created)) . $portal_user_key . base64_encode(strval($days_to_cookie_expiration_calc)))
		]));

		// Sets Cookie Days Till Expiration Until Depending If User Clicked On Remember

		$cookie_days = $cookie_not_remembered;

		if ($remember) {
			$cookie_days = $cookie_days_remember;
		} 

		if ($is_admin) {
			global $admin_cookie_name;
			setcookie($admin_cookie_name, $encoded, time() + ( $cookie_days * DAY_IN_SECONDS ), '/', '', 1, true);
		} else {
			global $user_cookie_name;
			setcookie($user_cookie_name, $encoded, time() + ( $cookie_days * DAY_IN_SECONDS ), '/', '', 1, true);
		}
	}

	// Get Cookie ID

	function get_cookie_id($encoded_cookie) {

		// Decode Cookie Values 

		$decoded_cookie = json_decode(base64_decode($encoded_cookie), true);

		// Return Cookie Id

		return $decoded_cookie['id'] ?? 'no user id';
	}

	function cookie_decoder($encoded_cookie) {

		// Decode Cookie Values 

		$decoded_cookie = json_decode(base64_decode($encoded_cookie, true));

		return $decoded_cookie;
	}

	// Check If Admin/User Portal Cookie Found Corresponds To An Admin/User In Database

    function verify_portal_cookie($type) {

		global $wpdb;
		global $admin_cookie;
		global $admin_table_name;
		global $select_portal_admins;

		// Check For Admin Cookie And See If Id In Cookie Corresponds To An Admin
		
		if ($type === 'admin' && isset($admin_cookie)) {
			$admins = $wpdb->get_results($select_portal_admins);

			$admin_cookie_id = get_cookie_id($admin_cookie);

			if ($admin_cookie_id) {
				foreach($admins as $admin) {
					if (strval($admin->ID) === strval($admin_cookie_id)) {

						// Decode Portal Admin Cookie

						$admin_cookie_decoded = cookie_decoder($admin_cookie);

						// Check That Cookie Has Not Gone Past Expiration Date

						if (intval($admin_cookie_decoded->expiration) < time()) {
							return false;
						}

						// Check That Type Is Admin

						if (strval($admin_cookie_decoded->type) !== 'admin') {
							return false;
						}

						global $portal_admin_key;

						// Check Portal Admin Key.  Signature Was Encoded With Created Date, Key, And Expiration Concatenated Together Before Hashing

						if (!wp_check_password(base64_encode(strval($admin->user_registered)) . $portal_admin_key . base64_encode(strval($admin_cookie_decoded->expiration)), $admin_cookie_decoded->signature)) {
							return false;
						}

						// If All Cookie Fields Passed, Return True

						return true;
					}
				}
			}

			// If Cookie Doesn't Correspond To An Admin User, Remove Invalid Cookie And Return False To Reject

			remove_portal_cookie();

			return false;
		}
		
		// Check For Portal User Cookie

			global $user_cookie;
		
		if ($type === 'user' && isset($user_cookie)) {
			global $portal_table_name;
			global $select_portal_users;
			$portal_users = $wpdb->get_results($select_portal_users);

			$user_cookie_id = get_cookie_id($user_cookie);

			if ($user_cookie_id) {
				foreach($portal_users as $user) {
					if (strval($user->id) === strval($user_cookie_id)) {

						// Decode Portal User Cookie

						$user_cookie_decoded = cookie_decoder($user_cookie);

						// Check That Creation Date Matches

						if (!wp_check_password(strval($user->created), $user_cookie_decoded->created)) {
							return false;
						}

						// Check That Cookie Has Not Gone Past Expiration Date

						if (intval($user_cookie_decoded->expiration) < time()) {
							return false;
						}

						// Check That Type Is Admin

						if (strval($user_cookie_decoded->type) !== 'user') {
							return false;
						}

						global $portal_user_key;

						// Check Portal User Key.  Signature Was Encoded With Created Date, Key, And Expiration Concatenated Together Before Hashing

						if (!wp_check_password(base64_encode(strval($user->created)) . $portal_user_key . base64_encode(strval($user_cookie_decoded->expiration)), $user_cookie_decoded->signature)) {
							return false;
						}

						// If All Cookie Fields Passed, Return True
						
						return true;
					}
				}
			}

			// If Cookie Doesn't Correspond To A Portal User, Return False To Reject

			remove_portal_cookie();

			return false;
		}
		
		// Return False To Reject If No Valid Cookies Present And Remove Invalid Cookie
		
		return false;
	}

	// Removes Admin/User Portal Cookies 

	function remove_portal_cookie() {

		global $admin_cookie_name;
		global $user_cookie_name;

		global $admin_cookie;
		global $user_cookie;
		
		// Remove Cookie Based On If User Has Admin Or Portal User Cookie To Logout
		
		if (isset($admin_cookie) && isset($user_cookie)) {
			setcookie($admin_cookie_name, 'logged_out', time() - 3600, '/', '', 0);
			setcookie($user_cookie_name, 'logged_out', time() - 3600, '/', '', 0);
			return rest_ensure_response(['message' => 'cookies for both portal admin and portal user found.  both removed.']);
		}
		
		if (isset($admin_cookie)) {
			setcookie($admin_cookie_name, 'logged_out', time() - 3600, '/', '', 0);
			return rest_ensure_response(['message' => 'portal admin logged out successfully.']);
		}
		
		if (isset($user_cookie)) {
			setcookie($user_cookie_name, 'logged_out', time() - 3600, '/', '', 0);
			return rest_ensure_response(['message' => 'portal user logged out successfully.']);
		}

		// Clear Cache Wordpress

		wp_cache_flush();

		// Clear Browser Data

		header('Clear-Site-Data: "cache"');
		
		// If No Admin Or Portal User Cookies Found, Throw Error
		
		return new WP_Error('no portal cookies found', 'unable to perform logout as no portal admin or user cookie found', ['status' => 400]);
	}

// PASSWORD ENCODE

	// Pre-Encode Portal User Password.  Password Storage Value Before Hashing

	function encode_password($password, $created) {
		global $portal_password_salt;

		return $password . base64_encode(strval($created)) . $portal_password_salt;
	}

// DATABASE INIT

    // Define Wordpress Database Methods And Database Table
    
	global $wpdb;

	global $portal_table_name;
	$charset_collate = $wpdb->get_charset_collate();

	// Checks If Client Portal Users Database 'portal_users' Exists And Creates It If It Does Not Exist

	if ($wpdb->get_var("SHOW TABLES LIKE '$portal_table_name'") != $portal_table_name) {
		$sql = "CREATE TABLE $portal_table_name (
			id mediumint(11) NOT NULL AUTO_INCREMENT,
			first_name varchar(100) NOT NULL,
			last_name varchar(100) NOT NULL,
			company varchar(255) NOT NULL,
            email varchar(100) NOT NULL,
            password varchar(255) NOT NULL,
			updated_password boolean NOT NULL default 0,
			sent_email boolean NOT NULL default 0,
			times_logged_in mediumint(11) NOT NULL default 0,
			last_login datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
            created datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
			updated datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
			PRIMARY KEY (id)
		) $charset_collate;";
		
		require_once( ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta( $sql );
	} 

// XSS MALICIOUS JAVASCRIPT CODE INJECTION ATTACK PREVENTION

	// Checks If Opening Or Closing Tag Is Present. If Found, Error Thrown

	function var_secure($var) {
		if (str_contains($var, '<') || str_contains($var, '>')) {
			return false;
		} else return true;
	}

// SEND EMAIL

    // Sends Email. Message Generated Based On Type

	function send_portal_user_email($type, $email, $password) {

		// Generate Message Based On Type (Create User, Forgotten Password, Admin Regenerate New User Password, Or Portal User Deleted)

		$subject_message = null;
		$type_message = null;

		switch($type) {
			case 'created':
				$subject_message = 'Magellan Portal User Created';
                $heading = "Welcome to the portal.";
				$type_message = 'You have been successfully registered to access the Magellan Portal. Please see your temporary password below and click the button to login.';
				break;
			case 'forgot':
				$subject_message = 'Magellan Portal User Password Recovery';
                $heading = "Hello again.";
				$type_message = 'You have requested to recover your password to the Magellan Portal. Please see your temporary password below and click the button to regain access to the Magellan Portal.';
				break;
			case 'regenerate':
				$subject_message = 'Magellan Portal User Password Reset By Admin';
                $heading = "Hello from the administrator.";
				$type_message = 'The Magellan Portal Administrator has reset your password. Please see your temporary password below and click the button to regain access.';
				break;
			case 'deleted':
				$subject_message = 'Magellan Portal User Deleted';
                $heading = "Thank you for exploring the portal.";
                $type_message = "We're glad you had the opportunity to explore the Magellan Portal.  Best of luck to you.";
				break;
		}

		// Check Arguments.  If Not All Required Arguments Present, Return False

		if (!$type || !$email) {
			return false;
		}

		if ($type !== 'deleted') {
			if (!$password || !$subject_message || !$type_message) {
				return false;
			}
		}

		// Email Template For Portal User Created, Password Reset

		$html_email_template = '
            <table cellspacing="0" cellpadding="0" style="background-image: url(http://www.partnerwithmagellan.com/wp-content/uploads/2023/02/email_background.jpg); background-color: black; background-repeat: no-repeat; background-position: center; background-size: cover; padding: 32px 16px; width: 100%;">
                <tbody style="margin: 0 auto;">
            
                    <!-- Magellan Financial Logo -->
            
                    <tr>
                        <td colspan="3" style="padding-bottom: 48px;" align="center">
                            <blockquote style="margin: 0; border:none;">
                                <img src="http://www.partnerwithmagellan.com/wp-content/uploads/2022/08/MAG-LOGO-HORZ-HEX-RevColor.svg" alt="" style="max-width: 428px;">
                            </blockquote>
                        </td>
                    </tr>
            
                    <!-- Main Section With Left Vertical Border -->
            
                    <tr width="400">
                        <td height="43" colspan="3" width="400" align="center" style="padding-bottom: 12px; padding-top: 16px;">
                            <blockquote style="margin: 0; max-width: 400px; margin: 0 auto; border-left: 4px #e3530f solid; padding-left: 24px;">
                                <p style="color: white; text-align: left; font-size: 32px; line-height: 36px; margin-bottom: 24px; padding-top: 8px;">
                                    <strong>'. $heading .'</strong>
                                </p>
                                <p style="color: white; text-align: left; font-size: 16px; line-height: 24px; margin: 0; padding-bottom: 8px;">
                                    '. $type_message .'
                                </p>
                            </blockquote>
                        </td>
                    </tr>
            
                    <!-- Password Info -->

                    <tr width="400">
                        <td colspan="3" height="27" width="400" align="center" style="padding-top: 16px;">
                            <blockquote style="margin: 0; max-width: 400px; margin: 0 auto; padding-left: 28px; border:none; min-width: 232px; white-space: nowrap;">
                                <p style="color: white; line-height: 22px; text-align: left;">
                                    <strong>Password: </strong>
                                    '. $password .'
                                </p>
                            </blockquote>
                        </td>
                    </tr>
            
                    <!-- Login Button -->
            
                    <tr width="400">
                        <td height="43" colspan="3" width="400" align="center" style="padding-top: 48px;">
                            <blockquote style="margin: 0; max-width: 400px; margin: 0 auto; padding-left: 28px; border:none; text-align: left;">
                                <a href="https://www.partnerwithmagellan.com/forge-resource-center-home/" target="_blank" style="text-decoration: none; text-align: center; max-width: 200px;" rel="noopener">
                                    <p style="color: white; font-size: 16px; line-height: 20px; margin: 0; background: #00000090; max-width: 200px; padding: 12px; border: 2px #e3530f solid; text-align: center;">
                                        <strong>CLICK HERE TO LOGIN</strong>
                                    </p>
                                </a>
                            </blockquote>
                        </td>
                    </tr>
                </tbody>
            </table>
		';

		// Email Template For User Deleted

		$deleted_user_html_template = '
            <table cellspacing="0" cellpadding="0" style="background-image: url(http://www.partnerwithmagellan.com/wp-content/uploads/2023/02/email_background.jpg); background-color: black; background-repeat: no-repeat; background-position: center; background-size: cover; padding: 32px 16px; width: 100%;">
                <tbody style="margin: 0 auto;">
            
                    <!-- Magellan Financial Logo -->
            
                    <tr>
                        <td colspan="3" style="padding-bottom: 48px;" align="center">
                            <blockquote style="margin: 0; border:none;">
                                <img src="http://www.partnerwithmagellan.com/wp-content/uploads/2022/08/MAG-LOGO-HORZ-HEX-RevColor.svg" alt="" style="max-width: 428px;">
                            </blockquote>
                        </td>
                    </tr>
            
                    <!-- Goodbye Section -->
            
                    <tr width="400">
                        <td height="43" colspan="3" width="400" align="center" style="padding-bottom: 12px; padding-top: 16px;">
                            <blockquote style="margin: 0; max-width: 400px; margin: 0 auto; border-left: 4px #e3530f solid; padding-left: 24px;">
                                <p style="color: white; text-align: left; font-size: 32px; line-height: 36px; margin-bottom: 24px; padding-top: 8px;">
                                    <strong>'. $heading .'</strong>
                                </p>
                                <p style="color: white; text-align: left; font-size: 16px; line-height: 24px; margin: 0; padding-bottom: 8px;">
                                    '. $type_message .'
                                </p>
                            </blockquote>
                        </td>
                    </tr>
                </tbody>
            </table>
        ';

		// Determine What Email Template To Use Based On $type Variable Value

		$email_output = null;

		if ($type === 'deleted') {
			$email_output = $deleted_user_html_template;
		} else $email_output = $html_email_template;
		
		// Email Headers

		$headers = [
            "From: noreply@partnerwithmagellan.com",
            "Content-type: text/html; charset=UTF-8"
        ];

		// Checks That Fields Are Secure

		if (!var_secure($email) || !var_secure($password)) {
			return false;
		}

		// Send Email

		$send_email = wp_mail($email, $subject_message, $email_output, $headers);

		// Check That Email Got Sent.  If So, True Is Returned.  Else False Is Returned

		return $send_email;
	}

// AUTHENTICATION

	// Verifies If User Is A Verified Portal Admin.  Checks Cookie Or Login Credentials

	function portal_admin($req) {
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $select_portal_admins;
		global $admin_table_name;
		$admins = $wpdb->get_results($select_portal_admins);
		
		// Check If Admin Table Is Empty.  Deny Access If Empty

		if ($admins === null || count($admins) === 0) {
			return new WP_Error('admin email/username and password not found', 'admin email/username and password not found as admin users table is currently empty', ['status' => 400]);
		}
		
		// Check If Admin Has Valid Cookie.  If So, Return True
		
		if (verify_portal_cookie('admin')) {
			return true;
		}
		
		// If No Cookie ID Was Found, Check For Admin Login Credentials In Body
		
		$body = json_decode($req->get_body());
		$admin_username = $body->admin_username ?? NULL;
		$admin_password = $body->admin_password ?? NULL;

		// Check If Username Includes "@" Email To See If email/username Only Was Provided

		$username_has_email = str_contains($admin_username, '@');
		
		// Check That Admin email/username And Password Is In Body.  If Not, Throw Error
		
		if (!$admin_username || !$admin_password) {
			return new WP_Error('invalid portal admin cookie. `admin_username` and `admin_password` fields required', 'admin email/username and password must be provided to execute this action since no portal admin or invalid cookie was found.', ['status' => 401]);
		}
		
		// Loop Through Admins In Table And Find Admin Corresponding To Email
		
		foreach($admins as $admin) {

			// Checks If Username Provided email/username Only And Adjust Accordingly

			$admin_db_username = null;

			if (!$username_has_email) {
				$admin_db_username = substr($admin->user_email, 0, strpos($admin->user_email, '@'));
			} else $admin_db_username = $admin->user_email;

			if (strtolower($admin_db_username) === strtolower($admin_username)) {

				// Check That Passwords Match

				$password_valid = wp_check_password($admin_password, $admin->user_pass);

				if (!$password_valid) {
					return new WP_Error('invalid admin password', 'admin password is invalid.', ['status' => 401]);
				} else {
					return true;
				}
			}
		}
		
		// If No Table Row Was Found With Corresponding Admin email/username, Deny Access
		
		return new WP_Error('invalid admin email/username', 'admin email/username is invalid.', ['status' => 401]);
	}

	// Verifies If User Is A Portal Admin Or User

	function portal_authorized($req) {
		
		// Check If User Is Admin And Has Valid Cookie And The ID That Corresponds To It Is A Valid User Admin ID
		
		if (verify_portal_cookie('admin')) {
			return true;
		}
		
		// Check If User Is Portal User And Has Valid Cookie And The ID That Corresponds To It Is A Valid Portal User ID
		
		if (verify_portal_cookie('user')) {
			return true;
		}

		// If No Portal Admin/User Cookies Found, Check For Credentials In Body

		// Get Body Parameters
		
		$body = json_decode($req->get_body());
		$admin_username = $body->admin_username ?? NULL;
		$admin_password = $body->admin_password ?? NULL;
		$user_email = $body->email ?? NULL;
		$user_password = $body->password ?? NULL;

		// Check If Username Includes "@" Email To See If email/username Only Was Provided

		$username_has_email = str_contains($admin_username, '@');

		// Define Wordpress Database Methods And Database Administrator And Portal Users Tables
		
		global $wpdb;
		
		// Check For Admin Credentials

		global $admin_table_name;
		global $select_portal_admins;
		$admins = $wpdb->get_results($select_portal_admins);

		if ($admin_username && $admin_password) {
			foreach($admins as $admin) {

				// Checks If Username Provided email/username Only And Adjust Accordingly

				$admin_db_username = null;

				if (!$username_has_email) {
					$admin_db_username = substr($admin->user_email, 0, strpos($admin->user_email, '@'));
				} else $admin_db_username = $admin->user_email;

				if (strtolower($admin_db_username) === strtolower($admin_username)) {
	
					// Check That Passwords Match
	
					$admin_password_valid = wp_check_password($admin_password, $admin->user_pass);
	
					if ($admin_password_valid) {
						return true;
					} 
				}
			}
		}
		
		// If No Admin Credentials Found, Check User Credentials
		
		global $portal_table_name;
		global $select_portal_users;
		$portal_users = $wpdb->get_results($select_portal_users);

		if ($user_email && $user_password) {
			foreach($portal_users as $user) {
				if (strtolower($user->email) === strtolower($user_email)) {
	
					// Check That Passwords Match
	
					$user_password_valid = wp_check_password($user_password, $user->password);
	
					if ($user_password_valid) {
						return true;
					} 
				}
			}
		}
		
		// If No Table Row For Admins Or Portal Users Was Found With Corresponding Cookie ID Or With Login Credentials, Deny Access
		
		return false;
	}

// CONTROLLERS

    // Method: POST
    // Route: /wp-json/portal/admin
    // Description: Portal Admin Login / Retrieve All Portal Users
    // Protected: True
	// Accessible By: Admin Only
    
	function get_portal_users($req) {

		// Get Body Data

		$body = json_decode($req->get_body());
		$admin_username = $body->admin_username ?? NULL;
		$admin_password = $body->admin_password ?? NULL;
		$remember = $body->remember ?? false;

		// Check If Username Includes "@" Email To See If email/username Only Was Provided

		$username_has_email = str_contains($admin_username, '@');
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		global $select_portal_admins;
		global $admin_table_name;
		$portal_users = $wpdb->get_results($select_portal_users);
		$admins = $wpdb->get_results($select_portal_admins);

		// Get Admin ID. Varialbe Initialized

		$admin_id = null;

		// Check For Cookie.  Otherwise Check For Email And Password In Body Parameters

		global $admin_cookie;

		if (verify_portal_cookie('admin')) {
			$admin_id = strval(get_cookie_id($admin_cookie));
		} else {
			foreach($admins as $admin) {

				// Checks If Username Provided email/username Only And Adjust Accordingly

				$admin_db_username = null;

				if (!$username_has_email) {
					$admin_db_username = substr($admin->user_email, 0, strpos($admin->user_email, '@'));
				} else $admin_db_username = $admin->user_email;

				if (strtolower($admin_db_username) === strtolower($admin_username)) {

					// Check That Passwords Match

					$password_valid = wp_check_password($admin_password, $admin->user_pass);

					if (!$password_valid) {
						return new WP_Error('password error', 'incorrect admin password entered', ['status' => 401]);
					} else {
						$admin_id = strval($admin->ID);

						// Clear Cache

						header('Clear-Site-Data: "cache"');

						// Generate Cookie For Portal Admin

						generate_portal_cookie($admin_id, true, $remember, $admin->user_registered);
					}
				}
			}
			if (!$admin_id) {

				// If No Admin ID Found, Throw Error

				return new WP_Error('unauthorized', 'please provide correct admin email/username and password credentials', ['status' => 401]);
			}
		}

		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {

			return rest_ensure_response(['message' => 'portal admin logged in successfully. portal users table is currently empty.', 'data' => []]);
		
		} else {

			// Sanitize Data To Avoid Execution Of Malicious Injected Code
			
			$sanitized_data = [];

			foreach($portal_users as $user) {
				$sanitized_row = [
					'id' => htmlspecialchars($user->id),
					'first_name' => htmlspecialchars($user->first_name),
					'last_name' => htmlspecialchars($user->last_name),
					'company' => htmlspecialchars($user->company),
					'email' => htmlspecialchars($user->email),
					'updated_password' => htmlspecialchars($user->updated_password),
					'sent_email' => htmlspecialchars($user->sent_email),
					'times_logged_in' => htmlspecialchars($user->times_logged_in),
					'last_login' => htmlspecialchars($user->last_login),
					'created' => htmlspecialchars($user->created),
					'updated' => htmlspecialchars($user->updated)
				];
				
				array_push($sanitized_data, $sanitized_row);
			}
			
			// Return Portal Users If Found In Table

			// Clear Cache

			header('Clear-Site-Data: "cache"');

			return rest_ensure_response(['message' => 'portal admin logged in successfully. portal users data retrieved successfully.', 'data' => $sanitized_data]);
		
		}
	}

	// Method: POST
    // Route: /wp-json/portal/user
    // Description: Create Portal User
    // Protected: True
	// Accessible By: Admin Only
    
	function create_portal_user($req) {
		
		// Decode Request Body Parameters And Assign To New Variables
		
		$params = json_decode($req->get_body());
		$first_name = $params->first_name ?? NULL;
		$last_name = $params->last_name ?? NULL;
		$company = $params->company ?? NULL;
		$email = $params->email ?? NULL;
		
		// Check If Any Required Fields Are Blank.  Error Thrown If Any Required Fields Are Empty
		
		if (!$first_name || !$last_name || !$company || !$email) {
			return new WP_Error('incomplete fields', 'please fill out the `first_name`, `last_name`, `company`, and `email` fields to register portal user.', ['status' => 400]);
		}

		// Checks That There Are No Script Tags To Avoid Malicious Code Injection

		if (!var_secure($first_name) || !var_secure($last_name) || !var_secure($company) || !var_secure($email)) {
			return new WP_Error('< or > detected', 'request will not be executed due to the presence of a potentially malicious code tag', ['status' => 403]);
		}
		
		// Capitalize First Character, LowerCase Remaining Characters For Appropriate Database Formatting.  Password Capitalization Doesn't Get Modified.
		
		$first_name = ucfirst(strtolower($first_name));
		$last_name = ucfirst(strtolower($last_name));
		$company = ucfirst(strtolower($company));
		$email = strtolower($email);
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		
		// Check That There Is Not The Same Existing Email In Database By Retrieving Portal Table From Database
		
		$existing_portal_users = $wpdb->get_results($select_portal_users);
		
		// Loops Through Table.  If Same Email Already Exists In Database, Error Thrown
		
		if (count($existing_portal_users) != 0) {
			foreach($existing_portal_users as $user) {
				if ($user->email === $email) {
					return new WP_Error('email already exists', 'a user with the same email already exists.', ['status' => 400]);
				}
			}
		}
		
		// Random Password Generation
		
		$random_password = wp_generate_password();
		
		// Password Hashing.  Portal User Creation Date And Portal Password Salt Added After Random Password

		// Created At Time
		
		$created = current_time('mysql', false);

		global $portal_password_salt;

		$pre_hash_password_encode = encode_password($random_password, $created);
		
		$hashed_password = wp_hash_password($pre_hash_password_encode);
		
		// Insert Fields Into Database Table

		$wpdb->insert($portal_table_name, array(
			'first_name' => htmlspecialchars($first_name), 
			'last_name' => htmlspecialchars($last_name), 
			'company' => htmlspecialchars($company), 
			'email' => htmlspecialchars($email), 
			'password' => $hashed_password,
			'updated_password' => 0,
			'sent_email' => 0,
			'times_logged_in' => 0,
			'created' => $created
		));
		
		// Check That Field Was Actually Inserted Into Database As A New Table Row

		global $select_portal_users;
		
		$updated_portal_users = $wpdb->get_results($select_portal_users);
		
		// Loops Through Table.  Checks That Row For Data Was Inserted
		
		if (count($updated_portal_users) != 0) {
			foreach($updated_portal_users as $usercheck) {
				if ($usercheck->first_name === $first_name && $usercheck->last_name === $last_name && $usercheck->email === $email) {
					
					// Checks Password.  If No Match, Throw Error
					
					if (wp_check_password($pre_hash_password_encode, $usercheck->password)) {

						// Send Email To Portal User.  If Email Fails, Throw Error

						if (!send_portal_user_email('created', $usercheck->email, $random_password)) {
							return new WP_Error('error sending email', 'user added to table, but email did not send.  try regenerating password to resend another email to portal user', ['status' => 500, 'id' => $usercheck->id, 'password' => $random_password, 'sent_email' => $usercheck->sent_email]);
						}

						// Update 'sent_email' Column To 1 In Table Row To Indicate Email Was Successfully Sent

						$wpdb->update($portal_table_name, array(
							'sent_email' => 1
						),
							array('id' => $usercheck->id)
						);

						// Check Database That 'sent_email' Column Was Updated Successfully

						$updated2_portal_users = $wpdb->get_results($select_portal_users);

						foreach($updated2_portal_users as $usercheck2) { 
							if ($usercheck->id === $usercheck2->id && strval($usercheck2->sent_email) === '1') {

								// Clear Cache

								header('Clear-Site-Data: "cache"');
								
								// API Response Upon Success

								return rest_ensure_response(['message' => 'portal user created successfully', 'data' => [
									'id' => htmlspecialchars($usercheck2->id),
									'first_name' => htmlspecialchars($usercheck2->first_name),
									'last_name' => htmlspecialchars($usercheck2->last_name),
									'company' => htmlspecialchars($usercheck2->company),
									'email' => htmlspecialchars($usercheck2->email),
									'updated_password' => htmlspecialchars($usercheck2->updated_password),
									'sent_email' => htmlspecialchars($usercheck2->sent_email),
									'times_logged_in' => htmlspecialchars($usercheck2->times_logged_in),
									'last_login' => htmlspecialchars($usercheck2->last_login),
									'created' => htmlspecialchars($usercheck2->created),
									'updated' => htmlspecialchars($usercheck2->updated)
								]]);
							}
						}

						// Clear Cache

						header('Clear-Site-Data: "cache"');

						// If Error In Updating 'sent_email' Column, Throw Error
						
						return new WP_Error('error updating `sent_email` column', 'portal user created and added to table and email successful, but error occured in updating column `sent_email` to indicate email sent. please manually checkoff that this portal user received an email.', ['status' => 500, 'id' => $usercheck->id, 'password' => $random_password, 'sent_email' => $usercheck->sent_email]);
						
					} else {
						return new WP_Error('error with portal user password', 'the password stored does not match up.  try regenerating password', ['status' => 500]);
					}
				}
			}
		}
		
		// If Rows Looped Through And No Matching Row Data Found, Error Thrown
		
		return new WP_Error('error inserting row', 'an error occured inserting new row in portal table in mysql', ['status' => 500]);
		
	};

	// Method: PUT
    // Route: /wp-json/portal/user/{id}
    // Description: Update Portal User by ID
    // Protected: True
	// Accessible By: Admin Or Portal User
    
	function update_portal_user($req) {
		// Get Params ID
		
		$user_id = $req->get_params()['id'];

		// Makes Sure If User Is Portal User And Not Administrator That Their Cookie Id Corresponds With Parameter User ID So They Cannot Modify Another Users Data

		$is_admin = verify_portal_cookie('admin');
		$is_user = verify_portal_cookie('user');

		global $user_cookie;

		if (!$is_admin && $is_user && strval(get_cookie_id($user_cookie)) !== strval($user_id)) {
			return new WP_Error('error updating user', 'portal user can only modify data corresponding to their account.', ['status' => 401]);
		}
		
		// Get Body Data
		
		$body = json_decode($req->get_body());
		$first_name = $body->first_name ?? NULL;
		$last_name = $body->last_name ?? NULL;
		$company = $body->company ?? NULL;
		$email = $body->email ?? NULL;
		$password = $body->password ?? NULL;
		
		// Checks That There Is At Least One Field To Update.  Otherwise Error Thrown
		
		if (!$first_name && !$last_name && !$company && !$email && !$password) {
			return new WP_Error('error updating user', 'no fields have been passed in to update.  portal user data will remain the same.', ['status' => 400]);
		}

		// Checks That There Are No Script Tags To Avoid Malicious Code Injection

		if (!var_secure($first_name) || !var_secure($last_name) || !var_secure($company) || !var_secure($email) || !var_secure($password)) {
			return new WP_Error('script tag detected', 'request will not be executed due to presence of a `<script>` tag.', ['status' => 403]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		$portal_users = $wpdb->get_results($select_portal_users);
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error updating user', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 
		
		// Loops Through Table.  Checks That User ID Exists And Then Updates
		
		foreach($portal_users as $user) {
			if (strval($user->id) === strval($user_id)) {

				// Declare Hashed Password Variable

				$hashed_password = null;

				// Extracts Existing Values From Request Body Fields That Were Not Passed In

				if (!$first_name) {
					$first_name = $user->first_name;
				}
				if (!$last_name) {
					$last_name = $user->last_name;
				}
				if (!$company) {
					$company = $user->company;
				}
				if ($email) {
					
					// Checks That Same Email Does Not Exist In Database For A Different User If Email Is In Body Or Request

					foreach($portal_users as $useremail) {
						if (strtolower($useremail->email) === strtolower($email) && strval($useremail->id) != strval($user_id)) {
							return new WP_Error('email already exists', 'a user with the same email already exists.', ['status' => 400]);
						}
					}
				}
				if (!$email) {
					$email = $user->email;
				}
				if ($password) {
					if (strlen($password) < 8) {
						return new WP_Error('not a secure password', 'password length must be at least 8 characters.', ['status' => 400]);
					}

					global $portal_password_salt;

					$hashed_password = wp_hash_password(encode_password($password, $user->created));
				}
				if (!$password) {
					$hashed_password = $user->password;
				}

				// Update Portal User Row

				$updated_at = current_time('mysql', false);
				
				// Capitalize First Character, LowerCase Remaining Characters For Appropriate Database Formatting.  Password Capitalization Doesn't Get Modified.
		
				$first_name = ucfirst(strtolower($first_name));
				$last_name = ucfirst(strtolower($last_name));
				$company = ucfirst(strtolower($company));
				$email = strtolower($email);

				$wpdb->update($portal_table_name, array(
					'first_name' => htmlspecialchars($first_name), 
					'last_name' => htmlspecialchars($last_name), 
					'company' => htmlspecialchars($company), 
					'email' => htmlspecialchars($email),
					'password' => $hashed_password,
					'updated' => $updated_at,
					'updated_password' => 1
				),
					array('id' => $user_id)
				);

				// Check That Portal User Row Was Updated

				$updated_portal_users = $wpdb->get_results($select_portal_users);

				// Loops Through Table.  Checks That Row For Data Was Inserted

				foreach($updated_portal_users as $usercheck) {
					if ($usercheck->first_name === $first_name && $usercheck->last_name === $last_name && $usercheck->company === $company && $usercheck->email === $email) {
						
						// Check Hashed Password In Row If Password Field Was Passed In To Update
	
						if ($password && !wp_check_password(encode_password($password, $usercheck->created), $usercheck->password)) {
							return new WP_Error('error updating password', 'portal user password did not update correctly.  try regenerating a new temporary password.', ['status' => 500]);
						}

						// Clear Cache

						header('Clear-Site-Data: "cache"');

						return rest_ensure_response(['message' => 'portal user updated successfully.', 'data' => ['id' => $usercheck->id]]);
					}
				}

				// If Error Occured In Updating Row In Mysql, Throw Error

				return new WP_Error('error inserting row', 'an error occured inserting new row in portal table in mysql', ['status' => 500]);

			}
		}
		
		// If No Rows That Correspond To User ID Found, Throw Error
		
		return new WP_Error('error updating user', 'portal user ID does not correspond to any user in portal table.', ['status' => 400]);
	};

	// Method: DELETE
    // Route: /wp-json/portal/user/{id}
    // Description: Delete Portal User
    // Protected: True
	// Accessible By: Admin Or Portal User
    
	function delete_portal_user($req) {
		// Get Params ID
		
		$user_id = $req->get_params()['id'];

		// Makes Sure If User Is Portal User And Not Administrator That Their Cookie Id Corresponds With Parameter User ID So They Cannot Modify Another Users Data

		$is_admin = verify_portal_cookie('admin');
		$is_user = verify_portal_cookie('user');

		global $user_cookie;

		if (!$is_admin && $is_user && strval(get_cookie_id($user_cookie)) !== strval($user_id)) {
			return new WP_Error('error updating user', 'portal user can only modify data corresponding to their account.', ['status' => 401]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		$portal_users = $wpdb->get_results($select_portal_users);
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error deleting user', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 

		// Gets User Email To Send Email Notifying Them Of Their Account Being Deleted

		$user_deleted_email = null;
		
		// Loops Through Table.  Checks That User ID Exists And Then Deletes
		
		$user_deleted = false;
		
		foreach($portal_users as $user) {
			if (strval($user->id) === strval($user_id)) {
				$wpdb->delete($portal_table_name, array('id' => $user_id));
				$user_deleted = true;
				$user_deleted_email = $user->email;
			}
		}
		
		// If No Table Row Was Found With Corresponding ID To Delete, Throw Error
		
		if(!$user_deleted) {
			return new WP_Error('cannot find user', 'no portal user with corresponding ID exists', ['status' => 400]);
		}
		
		// Check That Portal User Row Was Deleted

		$updated_portal_users = $wpdb->get_results($select_portal_users);

		// Loops Through Table.  Checks That Row Was Deleted

		if (count($updated_portal_users) != 0) {
			foreach($updated_portal_users as $usercheck) {
				if (strval($usercheck->id) === strval($user_id)) {
					return new WP_Error('error inserting row', 'an error occured inserting new row in portal table in mysql', ['status' => 500]);
				}
			}
		}

		// Send Email To Portal User Notifying Of Their Account Being Deleted.  If Email Fails, Throw Error

		if (!send_portal_user_email('deleted', $user_deleted_email, null)) {
			return new WP_Error('error sending email', 'user deleted, but email did not send to notify user.  send an email to the user informing them of this.', ['status' => 500, 'id' => $user_id]);
		}

		// Clear Cache

		header('Clear-Site-Data: "cache"');
		
		// If User Delete Was Successful, Return Success Message
		
		return rest_ensure_response(['message' => 'portal user deleted successfully and email sent notifying them of this.', 'data' => ['id' => $user_id]]);
	};


	// Method: POST
    // Route: /wp-json/portal/user/login
    // Description: Portal User Login / Get Portal User Data Upon Login
    // Protected: False
	// Accessible By: Public

	function login_portal_user($req) {

		// Get Body Email, Password, And Remember Checked Value
		
		$body = json_decode($req->get_body());
		$email = $body->email ?? NULL;
		$password = $body->password ?? NULL;
		$remember = $body->remember ?? false;

		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		$portal_users = $wpdb->get_results($select_portal_users);

		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('no portal users found', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 
		
		// Get User Id. Variable Initialized
		
		$user_id = null;

		// Check For Cookie.  Otherwise Check For Email And Password In Body Parameters

		global $user_cookie;

		if (verify_portal_cookie('user')) {
			$user_id = strval(get_cookie_id($user_cookie));
		} else {
			foreach($portal_users as $usercheck) {
				if (strtolower($usercheck->email) === strtolower($email)) {

					global $portal_password_salt;

					// Check That Passwords Match

					$password_valid = wp_check_password(encode_password($password, $usercheck->created), $usercheck->password);

					if (!$password_valid) {
						return new WP_Error('password error', 'incorrect password entered', ['status' => 401]);
					} else {
						$user_id = strval($usercheck->id);

						// Clear Cache

						header('Clear-Site-Data: "cache"');

						// Generate Cookie For Portal User.  If User Checked Remember Box, Then Cookie Set To Longer Expiration Time

						generate_portal_cookie($user_id, false, $remember, $usercheck->created);
					}
				}
			}
			if (!$user_id) {

				// If No Table Row Was Found With Corresponding Email, Throw Error

				return new WP_Error('unauthorized', 'please provide correct portal user email and password credentials', ['status' => 401]);
			}
		}
		
		// Check That Id Was Found Either By Cookie Or Email And Password In Body.  If Not, Throw Error
		
		if (!$user_id) {
			return new WP_Error('email and password required', 'the portal user email and password must be provided to login', ['status' => 401]);
		}

		// Loop Through Portal Users In Table And Find User Corresponding To ID
		
		foreach($portal_users as $user) {
			if (strval($user->id) === strval($user_id)) {

				// Update times_logged_in and last_login fields

				$current_time = current_time('mysql', false);

				$wpdb->update($portal_table_name, array(
					'times_logged_in' => number_format($user->times_logged_in) + 1,
					'last_login' => $current_time
				),
					array('id' => $user_id)
				);

				// Return API Response

				return rest_ensure_response(['message' => 'portal user logged in successfully.', 'data' => [
					'id' => htmlspecialchars($user->id), 
					'first_name' => htmlspecialchars($user->first_name),
					'last_name' => htmlspecialchars($user->last_name),
					'company' => htmlspecialchars($user->company),
					'email' => htmlspecialchars($user->email),
					'updated_password' => htmlspecialchars($user->updated_password),
					'sent_email' => htmlspecialchars($user->sent_email)
				]]);
			}
		}

		// If Data Could Not Be Returned, Throw Server Error

		return new WP_Error('error retrieving portal user data', 'therer was an error retrieving portal user data', ['status' => 500]);
	}

	// Method: POST
    // Route: /wp-json/portal/user/forgot
    // Description: Forgot Password Provide Email For Recovery
    // Protected: False
	// Accessible By: Public
    
	function forgot_password_portal_user($req) {
		// Get Body Email
		
		$body = json_decode($req->get_body());
		$email = $body->email ?? NULL;
		
		// Check That Email Is In Body.  If Not, Throw Error
		
		if (!$email) {
			return new WP_Error('email required', 'an email corresponding to the portal user must be provided.', ['status' => 400]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		$portal_users = $wpdb->get_results($select_portal_users);
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error in password recovery', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 
		
		// Loop Through Portal Users In Table And Find User Corresponding To Email
		
		foreach($portal_users as $user) {
			if (strtolower($user->email) === strtolower($email)) {
                // Random Temporary Password Generation
				
				$random_password = wp_generate_password();

				// Password Hashing.  Portal User Creation Date And Portal Password Salt Added After Random Password

				global $portal_password_salt;
		
				$hashed_password = wp_hash_password(encode_password($random_password, $user->created));

 				// Update User Table Row With Temporary Password

 				$updated_at = current_time('mysql', false);

 				$wpdb->update($portal_table_name, array(
					'password' => $hashed_password,
					'updated_password' => 0,
					'sent_email' => 0,
					'updated' => $updated_at
				),
					array('id' => $user->id)
				);

				// Send Email To Portal User.  If Email Fails, Throw Error

				if (!send_portal_user_email('forgot', $user->email, $random_password)) {
					return new WP_Error('error sending email', 'new temporary user password hashed to table, but email did not send.  try again.', ['status' => 500, 'email' => $email]);
				}

				$wpdb->update($portal_table_name, array(
					'sent_email' => 1
				),
					array('id' => $user->id)
				);

				// Check Database That 'sent_email' Column Was Updated Successful;y

				$updated_portal_users = $wpdb->get_results($select_portal_users);

				foreach($updated_portal_users as $usercheck) { 
					if ($user->id === $usercheck->id && strval($usercheck->sent_email) === '1') {

						// Clear Browser Data

						header('Clear-Site-Data: "cache"');
						
						// API Response Upon Success

						return rest_ensure_response(['message' => 'temporary password sent to corresponding email.', 'data' => ['email' => $email, 'sent_email' => $usercheck->sent_email]]);
					}
				}

				// Clear Browser Data

				header('Clear-Site-Data: "cache"');

				// If Error In Updating 'sent_email' Column, Throw Error
						
				return new WP_Error('error updating `sent_email` column', 'email sent, but failed to update `sent_email` column in table row.', ['status' => 500, 'email' => $email, 'sent_email' => '0']);
				
			}
		}
		
		// If No Table Row Was Found With Corresponding Email, Throw Error
		
		return new WP_Error('cannot find corresponding email', 'no portal user with corresponding email exists', ['status' => 400]);
	}

	// Method: POST
    // Route: /wp-json/portal/user/passwordreset/{id}
    // Description: Regenerate New Temporary Password For Portal User
    // Protected: True
	// Accessible By: Admin Only
    
	function reset_portal_user_password($req) {
		// Get Params ID
		
		$user_id = $req->get_params()['id'];
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		$portal_users = $wpdb->get_results($select_portal_users);
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error in resetting password', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 
		
		// Loop Through Portal Users In Table And Find User Corresponding To Request Parameter ID
		
		foreach($portal_users as $user) {
			if (strval($user->id) === strval($user_id)) {
                
				// Random Password Generation
		
				$random_password = wp_generate_password();

				// Password Hashing.  Portal User Creation Date And Portal Password Salt Added After Random Password
		
				$hashed_password = wp_hash_password(encode_password($random_password, $user->created));

				$updated_at = current_time('mysql', false);

				$wpdb->update($portal_table_name, array(
					'password' => $hashed_password,
					'sent_email' => 0,
					'updated' => $updated_at,
					'updated_password' => 0
				),
					array('id' => $user_id)
				);

				$updated_portal_users = $wpdb->get_results($select_portal_users);

				// Loops Through Table.  Checks That Row For Data Was Inserted.  Otherwise Error Thrown After Iterating Through Loop

				foreach($updated_portal_users as $usercheck) {
					if (strtolower($usercheck->id) === strtolower($user_id)) {
						if (wp_check_password(encode_password($random_password, $usercheck->created), $usercheck->password)) {

							// Send Email To Portal User.  If Email Fails, Throw Error

							if (!send_portal_user_email('regenerate', $usercheck->email, $random_password)) {
								return new WP_Error('error sending email', 'new temporary user password hashed to table, but email did not send.  try again.', ['status' => 500, 'id' => $user->id, 'password' => $random_password]);
							}

							// Update 'sent_email' Column To 1 In Table Row To Indicate Email Was Successfully Sent

							$wpdb->update($portal_table_name, array(
								'sent_email' => 1
							),
								array('id' => $usercheck->id)
							);

							// Check Database That 'sent_email' Column Was Updated Successfully

							$updated2_portal_users = $wpdb->get_results($select_portal_users);

							foreach($updated2_portal_users as $usercheck2) { 
								if ($usercheck->id === $usercheck2->id && strval($usercheck2->sent_email) === '1') {

									// Clear Cache

									header('Clear-Site-Data: "cache"');
									
									// API Response Upon Success

									return rest_ensure_response(['message' => 'portal user password reset successfully.', 'data' => ['id' => $user->id, 'password' => $random_password, 'sent_email' => $usercheck2->sent_email]]);
								}
							}

							// If Error In Updating 'sent_email' Column, Throw Error
						
							return new WP_Error('error updating `sent_email` column', 'new temporary password was regenerated and email sent, but failed to update `sent_email` column in table row to indicate email sent. please manually checkoff that this portal user received an email.', ['status' => 500, 'id' => $user->id, 'password' => $random_password, 'sent_email' => $usercheck->sent_email]);
							
						}
					} 
				}

				return new WP_Error('error inserting row', 'an error occured resetting portal user password in mysql', ['status' => 500]);
			}
		}
		
		// If No Table Row Was Found With Corresponding ID, Throw Error
		
		return new WP_Error('cannot find user', 'no portal user with corresponding ID exists', ['status' => 400]);
	}

	// Method: POST
    // Route: /wp-json/portal/user/emailsent/{id}
    // Description: Portal Admin Mark That Email Was Sent Manually To Portal User
    // Protected: True
	// Accessible By: Admin Only

	function sent_portal_user_email($req) {
		// Get Params ID
		
		$user_id = $req->get_params()['id'];
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		global $portal_table_name;
		global $select_portal_users;
		$portal_users = $wpdb->get_results($select_portal_users);
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error in resetting password', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 

		foreach($portal_users as $user) {
			if (strval($user->id) === strval($user_id)) {

				// Update 'sent_email' Column To 1 In Table Row To Indicate Email Was Successfully Sent Along With Updated Time

				$updated_at = current_time('mysql', false);
				
				$wpdb->update($portal_table_name, array(
					'sent_email' => 1,
					'updated' => $updated_at
				),
					array('id' => $user->id)
				);

				// Check Database That 'sent_email' Column Was Updated Successful

				$updated2_portal_users = $wpdb->get_results($select_portal_users);

				foreach($updated2_portal_users as $usercheck) { 
					if ($user->id === $usercheck->id && strval($usercheck->sent_email) === '1') {

						// Clear Cache

						header('Clear-Site-Data: "cache"');

						// API Response Upon Success

						return rest_ensure_response(['message' => 'portal user `sent_email` marked as being sent successfully', 'data' => ['id' => $user->id, 'sent_email' => $usercheck->sent_email]]);
					}
				}

				// If Error In Updating 'sent_email' Column, Throw Error
			
				return new WP_Error('error updating `sent_email` column', '`sent_email` column failed to update to indicate email was sent.  please try again', ['status' => 500, 'id' => $user->id, 'sent_email' => $usercheck->sent_email]);
			}
		}

		// If No Table Row Was Found With Corresponding ID, Throw Error
		
		return new WP_Error('cannot find user', 'no portal user with corresponding ID exists', ['status' => 400]);
	}

// ROUTES

	add_action( 'rest_api_init', function () { 
		
		// Admin Portal Login / Get Portal Users
		
		register_rest_route( 'portal', '/admin', [
			'methods' => 'POST',
			'permission_callback' => 'portal_admin',
			'callback' => 'get_portal_users'
		]);
		
		// Create Portal User
		
		register_rest_route( 'portal', '/user', [
			'methods' => 'POST',
			'permission_callback' => 'portal_admin',
			'callback' => 'create_portal_user'
		]);
		
		// Update Portal User
		
		register_rest_route( 'portal', '/user/(?P<id>[a-zA-Z0-9-]+)', [
			'methods' => 'PUT',
			'permission_callback' => 'portal_authorized',
			'callback' => 'update_portal_user'
		]);
		
		// Delete Portal User
		
		register_rest_route( 'portal', '/user/(?P<id>[a-zA-Z0-9-]+)', [
			'methods' => 'DELETE',
			'permission_callback' => 'portal_authorized',
			'callback' => 'delete_portal_user'
		]);

		// Login Portal User

		register_rest_route( 'portal', '/user/login', [
			'methods' => 'POST',
			'permission_callback' => '__return_true',
			'callback' => 'login_portal_user'
		]);
		
		// Portal User Forgot Temporary Password Create
		
		register_rest_route( 'portal', '/user/forgot', [
			'methods' => 'POST',
			'permission_callback' => '__return_true',
			'callback' => 'forgot_password_portal_user'
		]);
		
		// Portal Admin Create New Temporary Portal User Password
		
		register_rest_route( 'portal', '/user/passwordreset/(?P<id>[a-zA-Z0-9-]+)', [
			'methods' => 'POST',
			'permission_callback' => 'portal_admin',
			'callback' => 'reset_portal_user_password'
		]);

		// Portal Admin Mark That Email Was Sent Manually To Portal User
		
		register_rest_route( 'portal', '/user/emailsent/(?P<id>[a-zA-Z0-9-]+)', [
			'methods' => 'POST',
			'permission_callback' => 'portal_admin',
			'callback' => 'sent_portal_user_email'
		]);
		
		// Portal User/Admin Logout
		
		register_rest_route( 'portal', '/logout', [
			'methods' => 'POST',
			'permission_callback' => '__return_true',
			'callback' => 'remove_portal_cookie'
		]);
		
	});
?>
