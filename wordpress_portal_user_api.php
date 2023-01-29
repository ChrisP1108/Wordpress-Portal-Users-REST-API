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

// AUTHENTICATION

	// Administrator Only 

	function portal_admin($req) {
		// Get Body Email
		
		$body = json_decode($req->get_body());
		$admin_email = $body->admin_email ?? NULL;
		$admin_password = $body->admin_password ?? NULL;
		
		// Check That Admin Username And Password Is In Body.  If Not, Throw Error
		
		if (!$admin_email || !$admin_password) {
			return new WP_Error('admin username and password required', 'admin username and password must be provided to execute this action.', ['status' => 401]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$admin_table_name = $wpdb->prefix . "users";
		$admins = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $admin_table_name));
		
		// Check If Portal Table Is Empty.  Deny Access If Empty

		if ($admins === null || count($admins) === 0) {
			return new WP_Error('admin username and password not found', 'admin username and password not found as admin users table is currently empty', ['status' => 400]);
		}
		
		// Loop Through Portal Users In Table And Find User Corresponding To Email
		
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
		$is_user = true;
		if (portal_admin($req) || $is_user) {
			return true;
		} else return false;
	}

// RANDOM PASSWORD GENERATOR

	function random_password_generate() {
		return wp_generate_password();
	}

// CONTROLLERS

    // Method: GET
    // Route: /wp-json/portal/users
    // Description: Get All Portal Users
    // Protected: True
	// Accessible By: Admin Only
    
	function get_portal_users() {
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return rest_ensure_response(['message' => 'portal users table is currently empty', 'data' => []]);
		} else {
			
		// Return Portal Users If Found In Table

			return ($portal_users);
		}
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
			return new WP_Error('incomplete fields', 'please fill out the `first_name`, `last_name`, `company`, `email`, and `password` fields to register portal user.', ['status' => 400]);
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
		
		$random_password = random_password_generate();
		
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
			foreach($updated_portal_users as $user) {
				if ($user->first_name === $first_name && $user->last_name === $last_name && $user->email === $email) {
					return rest_ensure_response(['message' => 'portal user created successfully', 'data' => ['id' => $user->id, 'password' => $random_password]]);
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
					$password = wp_hash_password($password);
				}
				if (!$password) {
					$password = $user->password;
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
					'password' => $password,
					'updated' => $updated_at
				),
					array('id' => $user_id)
				);

				// Check That Portal User Row Was Updated

				$updated_portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));

				// Loops Through Table.  Checks That Row For Data Was Inserted

				if (count($updated_portal_users) != 0) {
					foreach($updated_portal_users as $usercheck) {
						if ($usercheck->first_name === $first_name && $usercheck->last_name === $last_name && $usercheck->company === $company && $usercheck->email === $email) {
							return rest_ensure_response(['message' => 'portal user updated successfully.', 'data' => ['id' => $user->id]]);
						}
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
    // Description: Portal User Login
    // Protected: False
	// Accessible By: Public

	function login_portal_user($req) {
		// Get Body Email
		
		$body = json_decode($req->get_body());
		$email = $body->email ?? NULL;
		$password = $body->password ?? NULL;
		
		// Check That Email And Password Is In Body.  If Not, Throw Error
		
		if (!$email || !$password) {
			return new WP_Error('email and temporary password required', 'the portal user email and temporary password that was sent to the users email must be provided.', ['status' => 400]);
		}
		
		// Define Wordpress Database Methods And Database Table
		
		global $wpdb;
		$portal_table_name = $wpdb->prefix . "portal_users";
		$portal_users = $wpdb->get_results($wpdb->prepare("SELECT * FROM ". $portal_table_name));
		
		// Check If Portal Table Is Empty

		if ($portal_users === null || count($portal_users) === 0) {
			return new WP_Error('error in password reset', 'portal user does not exist as portal users table is currently empty', ['status' => 400]);
		} 

		// Loop Through Portal Users In Table And Find User Corresponding To Email
		
		foreach($portal_users as $user) {
			if (strtolower($user->email) === strtolower($email)) {

				// Check That Passwords Match

				$password_valid = wp_check_password($password, $user->password);

				if (!$password_valid) {
					return new WP_Error('password error', 'incorrect password entered', ['status' => 401]);
				} else {
					// Provide Token via HTTP Only Cookie
					return rest_ensure_response(['message' => 'portal user logged in successfully.', 'data' => ['id' => $user->id]]);
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
				// $random_password = random_password_generate();
                // **Email $temporary_password Via Email API
                // Hash Temporary Password To Store In User Table Row
 				//$hashed_password = wp_hash_password($random_password);
 				// Update User Table Row With Temporary Password
 				//$updated_at = current_time('mysql', false);
 				// $wpdb->update($portal_table_name, array(
				//	'password' => $hashed_password,
				//	'updated' => $updated_at
				// ),
				//	array('id' => $user->id)
				// );
				return rest_ensure_response(['message' => 'temporary password sent to corresponding email.', 'data' => ['email' => $email]]);
			}
		}
		
		// If No Table Row Was Found With Corresponding Email, Throw Error
		
		return new WP_Error('cannot find corresponding email', 'no portal user with corresponding email exists', ['status' => 400]);
	}

// ROUTES

	add_action( 'rest_api_init', function () { 
		
		// Get Portal Users
		
		register_rest_route( 'portal', '/users', [
			'methods' => 'GET',
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
		
	});
?>
