<?php
// DATABASE INIT

    // Define Wordpress Database Methods And Database Table
    
	global $wpdb;

	$portal_table_name = $wpdb->prefix . "portal_users";
	$charset_collate = $wpdb->get_charset_collate();

	// Checks If Client Portal Users Database ('custom_portal_users') Exists And Creates It If It Does Not Exist

	if ($wpdb->get_var("SHOW TABLES LIKE '$portal_table_name'") != $portal_table_name) {
		$sql = "CREATE TABLE $table_name (
			id mediumint(11) NOT NULL AUTO_INCREMENT,
			first_name varchar(100) NOT NULL,
			last_name varchar(100) NOT NULL,
			company varchar(255) NOT NULL,
            email varchar(100) NOT NULL,
            password varchar(255) NOT NULL,
			is_active boolean NOT NULL default 0,
            created datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
			updated datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
			PRIMARY KEY (id)
		) $charset_collate;";
		
		require_once( ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta( $sql );
	} 

// COOKIE GENERATOR

	function generate_cookie($id, $is_admin) {

		$id_multiplied = strval(intval($id) * 237);

		// Salt Concatenation Before Scrambling

		$id_salted = strval(rand(1000, 9999)) . $id_multiplied . strval(rand(1000, 9999));

		// Cookie Scrambling Algorithm

		$id_split = str_split($id_salted);
		$id_scrambled = '';
		foreach($id_split as $int) {
			switch ($int) {
				case "0":
					$id_scrambled = $id_scrambled . "$";
					break;	
				case "1":
					$id_scrambled = $id_scrambled . "e";
					break;	
				case "2":
					$id_scrambled = $id_scrambled . "*";
					break;
				case "3":
					$id_scrambled = $id_scrambled . "7";
					break;	
				case "4":
					$id_scrambled = $id_scrambled . "W";
					break;
				case "5":
					$id_scrambled = $id_scrambled . "1";
					break;
				case "6":
					$id_scrambled = $id_scrambled . "?";
					break;
				case "7":
					$id_scrambled = $id_scrambled . "p";
					break;
				case "8":
					$id_scrambled = $id_scrambled . "Z";
					break;
				case "9":
					$id_scrambled = $id_scrambled . "3";
					break;
			}
		}

		// Sets Cookie Based On If User Is Admin Or Portal User

		if ($is_admin) {
			setcookie('portal_admin', $id_scrambled, time() + ( 7 * DAY_IN_SECONDS ), '/', '', 1, true);
		} else {
			setcookie('portal_user', $id_scrambled, time() + ( 7 * DAY_IN_SECONDS ), '/', '', 1, true);
		}
	}

	function unscramble_cookie($scrambled_cookie) {

		// Salt Removal

		$scrambled_cookie = substr($scrambled_cookie, 4, -4);

		// Cookie Unscrambling Algorithm

		$split_scrambled_cookie = str_split($scrambled_cookie);

		$id_unscrambled = '';

		foreach($split_scrambled_cookie as $int) {
			switch ($int) {
				case "$":
					$id_unscrambled = $id_unscrambled . "0";
					break;	
				case "e":
					$id_unscrambled = $id_unscrambled . "1";
					break;	
				case "*":
					$id_unscrambled = $id_unscrambled . "2";
					break;
				case "7":
					$id_unscrambled = $id_unscrambled . "3";
					break;	
				case "W":
					$id_unscrambled = $id_unscrambled . "4";
					break;
				case "1":
					$id_unscrambled = $id_unscrambled . "5";
					break;
				case "?":
					$id_unscrambled = $id_unscrambled . "6";
					break;
				case "p":
					$id_unscrambled = $id_unscrambled . "7";
					break;
				case "Z":
					$id_unscrambled = $id_unscrambled . "8";
					break;
				case "3":
					$id_unscrambled = $id_unscrambled . "9";
					break;
			}
		}
		
		return strval(intval($id_unscrambled) / 237);	
	}

    function verify_cookie($is_admin) {

		global $wpdb;
		
		// Check For Admin Cookie And See If Id In Cookie Corresponds To An Admin
		
		if ($is_admin && isset($_COOKIE["portal_admin"])) {
			$admin_table_name = $wpdb->prefix . "users";
			$admins = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $admin_table_name));

			$admin_cookie_id = unscramble_cookie($_COOKIE["portal_admin"]);
		
			foreach($admins as $admin) {
				if (strval($admin->ID) === strval($admin_cookie_id)) {
					return true;
				}
			}

			// If Cookie Doesn't Correspond To An Admin User, Return False To Reject

			return false;
		}
		
		// Check For Portal User Cookie
		
		if (!$is_admin && isset($_COOKIE["portal_user"])) {
			$portal_table_name = $wpdb->prefix . "portal_users";
			$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));

			$user_cookie_id = unscramble_cookie($_COOKIE["portal_user"]);

			foreach($portal_users as $user) {
				if (strval($user->id) === strval($user_cookie_id)) {
					return true;
				}
			}

			// If Cookie Doesn't Correspond To A Portal User, Return False To Reject

			return false;
		}
		
		// Return False To Reject If No Valid Cookies Present
		
		return false;
	}

	function destroy_cookie() {
		
		// Remove Cookie Based On If User Has Admin Or Portal User Cookie To Logout
		
		if (isset($_COOKIE["portal_admin"]) && isset($_COOKIE["portal_user"])) {
			setcookie('portal_admin', 'logged_out', time() - 3600, '/', '', 0);
			setcookie('portal_user', 'logged_out', time() - 3600, '/', '', 0);
			return rest_ensure_response(['message' => 'cookies for both portal admin and portal user found.  both removed.']);
		}
		
		if (isset($_COOKIE["portal_admin"])) {
			setcookie('portal_admin', 'logged_out', time() - 3600, '/', '', 0);
			return rest_ensure_response(['message' => 'portal admin logged out successfully.']);
		}
		
		if (isset($_COOKIE["portal_user"])) {
			setcookie('portal_user', 'logged_out', time() - 3600, '/', '', 0);
			return rest_ensure_response(['message' => 'portal user logged out successfully.']);
		}
		
		// If No Admin Or Portal User Cookies Found, Throw Error
		
		return new WP_Error('no portal cookies found', 'unable to perform logout as no portal admin or user cookie found', ['status' => 400]);
	}

// AUTHENTICATION

	// Administrator Only 

	function portal_admin($req) {
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$admin_table_name = $wpdb->prefix . "users";
		$admins = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $admin_table_name));
		
		// Check If Admin Table Is Empty.  Deny Access If Empty

		if ($admins === null || count($admins) === 0) {
			return new WP_Error('admin username and password not found', 'admin username and password not found as admin users table is currently empty', ['status' => 400]);
		}
		
		// Check If Admin Has Valid Cookie.  If So, Return True
		
		$valid_admin_cookie = verify_cookie(true);
		
		if ($valid_admin_cookie) {
			return true;
		}
		
		// If No Cookie ID Was Found, Check For Admin Login Credentials
			
		// Get Body Email
		
		$body = json_decode($req->get_body());
		$admin_email = $body->admin_email ?? NULL;
		$admin_password = $body->admin_password ?? NULL;
		
		// Check That Admin Username And Password Is In Body.  If Not, Throw Error
		
		if (!$admin_email || !$admin_password) {
			return new WP_Error('no portal admin cookie. `admin_username` and `admin_password` fields required', 'admin username and password must be provided to execute this action since no portal admin cookie was found.', ['status' => 401]);
		}
		
		// Loop Through Admins In Table And Find Admin Corresponding To Email
		
		foreach($admins as $admin) {
			if (strtolower($admin->user_email) === strtolower($admin_email)) {

				// Check That Passwords Match

				$password_valid = wp_check_password($admin_password, $admin->user_pass);

				if (!$password_valid) {
					return new WP_Error('invalid admin password', 'admin password is invalid.', ['status' => 401]);
				} else {
					return true;
				}
			}
		}
		
		// If No Table Row Was Found With Corresponding Admin Email, Deny Access
		
		return new WP_Error('invalid admin email', 'admin email is invalid.', ['status' => 401]);
	}

	// Administrator Or Portal User

	function portal_authorized($req) {
		
		// Define Wordpress Database Methods And Database Administrator And Portal Users Tables
		
		global $wpdb;
		
		// Admins
		
		$admin_table_name = $wpdb->prefix . "users";
		$admins = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $admin_table_name));
		
		// Portal Users
		
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Check If User Is Admin And Has Valid Cookie And The ID That Corresponds To It Is A Valid User Admin ID
		
		$cookie_admin_id = verify_cookie(true);
		
		if ($cookie_admin_id) {
			return true;
		}
		
		// Check If User Is Portal User And Has Valid Cookie And The ID That Corresponds To It Is A Valid Portal User ID
		
		$cookie_portal_user_id = verify_cookie(false);
		
		if ($cookie_portal_user_id) {
			return true;
		}
		
		// If No Table Row For Admins Or Portal Users Was Found With Corresponding Cookie ID, Deny Access
		
		return false;
	}

// CONTROLLERS

    // Method: POST
    // Route: /wp-json/portal/admin
    // Description: Portal Admin Login / Retrieve All Portal Users
    // Protected: True
	// Accessible By: Admin Only
    
	function get_portal_users($req) {

		$body = json_decode($req->get_body());
		$admin_email = $body->admin_email ?? NULL;
		$admin_password = $body->admin_password ?? NULL;
		
		// Check That Email And Password Is In Body.  If Not, Throw Error
		
		if (!$admin_email || !$admin_password) {
			return new WP_Error('admin email and admin password required', 'the portal admin email and password must be provided to login to admin dashboard', ['status' => 400]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$admin_table_name = $wpdb->prefix . "users";
		$admins = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $admin_table_name));

		// Check If Portal Table Is Empty.  Deny Access If Empty

		if ($admins === null || count($admins) === 0) {
			return new WP_Error('admin username and password not found', 'admin username and password not found as admin users table is currently empty', ['status' => 400]);
		}

		// Init Admin ID Variable

		$admin_id = null;

		// Loop Through Admins In Table And Find Admin Corresponding To Email
		
		foreach($admins as $admin) {
			if (strtolower($admin->user_email) === strtolower($admin_email)) {

				// Check That Passwords Match

				$password_valid = wp_check_password($admin_password, $admin->user_pass);

				if (!$password_valid) {
					return new WP_Error('invalid admin password', 'admin password is invalid.', ['status' => 401]);
				} else {
					$admin_id = $admin->ID;
				}
			}
		}

		if ($admin_id) {
			$portal_table_name = $wpdb->prefix . "portal_users";
			$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
			
			// Check If Portal Table Is Empty

			if ($portal_users === null || count($portal_users) === 0) {
				generate_cookie($admin->ID, true);
				return rest_ensure_response(['message' => 'portal admin logged in successfully. portal users table is currently empty.', 'data' => []]);
			} else {
				
			// Return Portal Users If Found In Table
				generate_cookie($admin->ID, true);
				return rest_ensure_response(['message' => 'portal admin logged in successfully. portal users data retrieved successfully.', 'data' => $portal_users]);
			}
		}

		return new WP_Error('invalid admin email', 'no admin with found with corresponding email.', ['status' => 401]);
	};

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
		
		// Capitalize First Character, LowerCase Remaining Characters For Appropriate Database Formatting.  Password Capitalization Doesn't Get Modified.
		
		$first_name = ucfirst(strtolower($first_name));
		$last_name = ucfirst(strtolower($last_name));
		$company = ucfirst(strtolower($company));
		$email = strtolower($email);
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$portal_table_name = $wpdb->prefix . "portal_users";
		
		// Check That There Is Not The Same Existing Email In Database By Retrieving Portal Table From Database
		
		$existing_portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
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
		
		// Password Hashing
		
		$hashed_password = wp_hash_password($random_password);
		
		// Created At Time
		
		$created = current_time('mysql', false);
		
		// Insert Fields Into Database Table

		$wpdb->insert($portal_table_name, array(
			'first_name' => $first_name, 
			'last_name' => $last_name, 
			'company' => $company, 
			'email' => $email, 
			'password' => $hashed_password,
			'is_active' => 0,
			'created' => $created
		));
		
		// Check That Field Was Actually Inserted Into Database As A New Table Row
		
		$updated_portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Loops Through Table.  Checks That Row For Data Was Inserted
		
		if (count($updated_portal_users) != 0) {
			foreach($updated_portal_users as $usercheck) {
				if ($usercheck->first_name === $first_name && $usercheck->last_name === $last_name && $usercheck->email === $email) {
					
					// Checks Password.  If No Match, Throw Error
					
					if (wp_check_password($random_password, $usercheck->password)) {
						return rest_ensure_response(['message' => 'portal user created successfully', 'data' => ['id' => $usercheck->id, 'password' => $random_password]]);
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

		$is_admin = verify_cookie(true);
		$is_user = verify_cookie(false);

		if (!$is_admin && $is_user && strval(unscramble_cookie($_COOKIE["portal_user"])) !== strval($user_id)) {
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
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
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
					$hashed_password = wp_hash_password($password);
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
					'first_name' => $first_name, 
					'last_name' => $last_name, 
					'company' => $company, 
					'email' => $email,
					'password' => $hashed_password,
					'updated' => $updated_at,
					'is_active' => 1
				),
					array('id' => $user_id)
				);

				// Check That Portal User Row Was Updated

				$updated_portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));

				// Loops Through Table.  Checks That Row For Data Was Inserted

				foreach($updated_portal_users as $usercheck) {
					if ($usercheck->first_name === $first_name && $usercheck->last_name === $last_name && $usercheck->company === $company && $usercheck->email === $email) {
						
						// Check Hashed Password In Row If Password Field Was Passed In To Update
	
						if ($password && !wp_check_password($password, $usercheck->password)) {
							return new WP_Error('error updating password', 'portal user password did not update correctly.  try regenerating a new temporary password.', ['status' => 500]);
						}

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

		$is_admin = verify_cookie(true);
		$is_user = verify_cookie(false);

		if (!$is_admin && $is_user && strval(unscramble_cookie($_COOKIE["portal_user"])) !== strval($user_id)) {
			return new WP_Error('error updating user', 'portal user can only modify data corresponding to their account.', ['status' => 401]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error deleting user', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 
		
		// Loops Through Table.  Checks That User ID Exists And Then Deletes
		
		$user_deleted = false;
		
		foreach($portal_users as $user) {
			if (strval($user->id) === strval($user_id)) {
				$wpdb->delete($portal_table_name, array('id' => $user_id));
				$user_deleted = true;
			}
		}
		
		// If No Table Row Was Found With Corresponding ID To Delete, Throw Error
		
		if(!$user_deleted) {
			return new WP_Error('cannot find user', 'no portal user with corresponding ID exists', ['status' => 400]);
		}
		
		// Check That Portal User Row Was Deleted

		$updated_portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));

		// Loops Through Table.  Checks That Row Was Deleted

		if (count($updated_portal_users) != 0) {
			foreach($updated_portal_users as $usercheck) {
				if (strval($usercheck->id) === strval($user_id)) {
					return new WP_Error('error inserting row', 'an error occured inserting new row in portal table in mysql', ['status' => 500]);
				}
			}
		}
		
		// If User Delete Was Successful, Return Success Message
		
		return rest_ensure_response(['message' => 'portal user deleted successfully.', 'data' => ['id' => $user_id]]);
	};


	// Method: POST
    // Route: /wp-json/portal/user/login
    // Description: Portal User Login / Get Portal User Data Upon Login
    // Protected: False
	// Accessible By: Public

	function login_portal_user($req) {
		// Get Body Email
		
		$body = json_decode($req->get_body());
		$email = $body->email ?? NULL;
		$password = $body->password ?? NULL;
		
		// Check That Email And Password Is In Body.  If Not, Throw Error
		
		if (!$email || !$password) {
			return new WP_Error('email and password required', 'the portal user email and password must be provided to login', ['status' => 400]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('no portal users found', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 

		// Loop Through Portal Users In Table And Find User Corresponding To Email
		
		foreach($portal_users as $user) {
			if (strtolower($user->email) === strtolower($email)) {

				// Check That Passwords Match

				$password_valid = wp_check_password($password, $user->password);

				if (!$password_valid) {
					return new WP_Error('password error', 'incorrect password entered', ['status' => 401]);
				} else {
					generate_cookie($user->id, false);
					return rest_ensure_response(['message' => 'portal user logged in successfully.', 'data' => [
						'id' => $user->id, 
						'first_name' => $user->first_name,
						'last_name' => $user->last_name,
						'company' => $user->company,
						'email' => $user->email
					]]);
				}
			}
		}
		
		// If No Table Row Was Found With Corresponding Email, Throw Error
		
		return new WP_Error('cannot find user', 'no portal user with corresponding email exists', ['status' => 400]);
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
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error in password recovery', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 
		
		// Loop Through Portal Users In Table And Find User Corresponding To Email
		
		foreach($portal_users as $user) {
			if (strtolower($user->email) === strtolower($email)) {
                // Random Temporary Password Generation
				// $random_password = wp_generate_password();
                // **Email $temporary_password Via Email API
                // Hash Temporary Password To Store In User Table Row
 				//$hashed_password = wp_hash_password($random_password);
 				// Update User Table Row With Temporary Password
 				//$updated_at = current_time('mysql', false);
 				// $wpdb->update($portal_table_name, array(
				//	'password' => $hashed_password,
				//	'updated' => $updated_at,
				//	'is_active' => 0
				// ),
				//	array('id' => $user->id)
				// );
				return rest_ensure_response(['message' => 'temporary password sent to corresponding email.', 'data' => ['email' => $email]]);
			}
		}
		
		// If No Table Row Was Found With Corresponding Email, Throw Error
		
		return new WP_Error('cannot find corresponding email', 'no portal user with corresponding email exists', ['status' => 400]);
	}

	// Method: GET
    // Route: /wp-json/portal/user/{id}/resetpassword
    // Description: Regenerate New Temporary Password For Portal User
    // Protected: True
	// Accessible By: Admin Only
    
	function reset_portal_user_password($req) {
		// Get Params ID
		
		$user_id = $req->get_params()['id'];
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error in resetting password', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 
		
		// Loop Through Portal Users In Table And Find User Corresponding To Request Parameter ID
		
		foreach($portal_users as $user) {
			if (strval($user->id) === strval($user_id)) {
                
				// Random Password Generation
		
				$random_password = wp_generate_password();

				// Update Portal User Row

				$updated_at = current_time('mysql', false);

				$wpdb->update($portal_table_name, array(
					'first_name' => $user->first_name, 
					'last_name' => $user->last_name, 
					'company' => $user->company, 
					'email' => $user->email,
					'password' => wp_hash_password($random_password),
					'updated' => $updated_at,
					'is_active' => 0
				),
					array('id' => $user_id)
				);

				$updated_portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));

				// Loops Through Table.  Checks That Row For Data Was Inserted.  Otherwise Error Thrown After Iterating Through Loop

				foreach($updated_portal_users as $usercheck) {
					if (strtolower($usercheck->id) === strtolower($user_id)) {
						if (wp_check_password($random_password, $usercheck->password)) {
							return rest_ensure_response(['message' => 'portal user password reset successfully.', 'data' => ['id' => $user->id, 'password' => $random_password]]);
						}
					} 
				}

				return new WP_Error('error inserting row', 'an error occured resetting portal user password in mysql', ['status' => 500]);
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
			'callback' => 'login_portal_user'
		]);
		
		// Portal User Forgot Temporary Password Create
		
		register_rest_route( 'portal', '/user/forgot', [
			'methods' => 'POST',
			'callback' => 'forgot_password_portal_user'
		]);
		
		// Portal Admin Create New Temporary Portal User Password
		
		register_rest_route( 'portal', '/user/passwordreset/(?P<id>[a-zA-Z0-9-]+)', [
			'methods' => 'GET',
			'permission_callback' => 'portal_admin',
			'callback' => 'reset_portal_user_password'
		]);
		
		// Portal User/Admin Logout
		
		register_rest_route( 'portal', '/logout', [
			'methods' => 'POST',
			'callback' => 'destroy_cookie'
		]);
		
	});

// PAGE ACCESS RESTRICTIONS

	// Allows Access To Portal Pages Only If Portal User Or Portal Admin Cookie Present. If Not, Redirected To Portal User Login
	
	add_action('template_redirect', function() {
		if (is_page('portal-page-1') || is_page('portal-page-2')) {
			if (!verify_cookie(true) && !verify_cookie(false)) {
				wp_redirect( 'http://localhost/wordpress_test/login-page/' ); 
				exit();
			}
		}
	});
?>
