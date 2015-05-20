<?php
/*
Plugin Name: Cluster login
Plugin URI: http://www.geniem.com
Description: A plugin that logs user in to multiple instances of the same site at once
Author: Miika Arponen / Geniem Oy
Author URI: http://www.geniem.com
Version: 0.0.1
*/

class Cluster_Login {
	
	public function __construct() {
		add_action("init", array( $this, "check_login" ) );
		if ( is_admin() && ! defined('DOING_AJAX') ) {
			add_action("admin_init", array( $this, "admin_stuff" ) );
		}
		add_action("wp_logout", array( $this, "logout" ) );
		add_action("login_enqueue_scripts", array( $this, "custom_login" ) );

		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}
	}

	public function check_login() {
		if ( ! is_user_logged_in() ) {
			if ( preg_match( "/cluster_login_token=([^&]+)&?/", $_SERVER["REQUEST_URI"], $matches ) ) {
				$compare_token = md5($_SERVER["HTTP_USER_AGENT"] . "#ß°¶0bÄæ"); // . $_SERVER['REMOTE_ADDR']);

				if ( strpos( $matches[1], $compare_token ) === false ) {
					return;
				}

				// find out if the token exists and get the user for it
				$users = get_users( array( "meta_key" => "_cluster_login_token",
										   "meta_value" => $matches[1]
										 ) );

				if ( empty( $users ) ) {					
					return;
				}

				$user = $users[0];

				// get the timestamp from the database
				$timestamp = get_user_meta( $user->ID, "_cluster_login_timestamp", true );

				// if the timestamp is not too old, log the user in
				if ( isset( $timestamp ) && ( time() - $timestamp < 300 ) ) {					
					wp_set_current_user( $user->ID, $user->user_login );
			        wp_set_auth_cookie( $user->ID );
			        do_action( 'wp_login', $user->user_login );
				}

				// delete the token and timestamp from the database to prevent misuse
				delete_user_meta( $user->ID, "_cluster_login_token" );
				delete_user_meta( $user->ID, "_cluster_login_timestamp" );

				return;
			}
		}
		else if ( preg_match( "/cluster_logout/", $_SERVER["REQUEST_URI"] ) ) {
			wp_logout();
		}
	}

	public function admin_stuff() {
		if ( preg_match( "/cluster_logout/", $_SERVER["REQUEST_URI"] ) ) {
			wp_logout();
		}
		else if ( isset( $_SESSION["cluster_login_done"] ) ) {
			return;
		}
		else {
			$user_id = get_current_user_id();

			delete_user_meta( $user_id, "_cluster_login_token" );
			delete_user_meta( $user_id, "_cluster_login_timestamp" );

			// register the javascript code we need
			wp_register_script( "cluster_login", plugin_dir_url( __FILE__ ) . "/js/cluster-login.js", array("jquery"), "0.01" );

			// create the token
			$token = md5($_SERVER["HTTP_USER_AGENT"] . "#ß°¶0bÄæ") . substr( md5(microtime()), 3, 8 ); // . $_SERVER['REMOTE_ADDR']);

			// initialize the data
			$data = array();
			$data["url"] = WP_PUB_SITEURL;
			$data["token"] = $token;

			// pass the data to javascript
			wp_localize_script( "cluster_login", "cluster_login_data", $data );

			// enqueue the javascript
			wp_enqueue_script("cluster_login");

			// insert the token into database
			add_user_meta( $user_id, "_cluster_login_token", $token, true );			
			// insert timestamp into database
			add_user_meta( $user_id, "_cluster_login_timestamp", time(), true );

			$_SESSION["cluster_login_done"] = true;
		}
	}

	public function logout() {
		unset($_SESSION["cluster_login_done"]);
	}

	public function custom_login() {
		if ( preg_match( "/loggedout/", $_SERVER["REQUEST_URI"] ) ) {
			// register the javascript code we need
			wp_register_script( "cluster_login", plugin_dir_url( __FILE__ ) . "/js/cluster-login.js", array("jquery"), "0.01" );

			// initialize the data
			$data = array();

			$nonce = wp_create_nonce( "logout" );

			if ( preg_match( "/admin/", $_SERVER['SERVER_NAME'] ) ) {
				$data["url"] = WP_PUB_SITEURL ."/?cluster_logout";	
			}
			else {
				$data["url"] = WP_ADMIN_URL ."/?cluster_logout";
			}

			// pass the data to javascript
			wp_localize_script( "cluster_login", "cluster_login_data", $data );

			// enqueue the javascript
			wp_enqueue_script("cluster_login");
		}
	}

}

	if ( !function_exists('wp_verify_nonce') ) :
	function wp_verify_nonce( $nonce, $action = -1 ) {
	        $nonce = (string) $nonce;
	        $user = wp_get_current_user();
	        $uid = (int) $user->ID;
	        if ( ! $uid ) {
	                $uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
	        }

	        if ( empty( $nonce ) ) {
	                return false;
	        }

	        $token = md5($_SERVER["HTTP_USER_AGENT"] . "#ß°¶0bÄæ"); // . $_SERVER['REMOTE_ADDR']);
	        $i = wp_nonce_tick();

	        // Nonce generated 0-12 hours ago
	        $expected = substr( wp_hash( $i . '|' . $action . '|' . $uid . '|' . $token, 'nonce'), -12, 10 );
	        if ( hash_equals( $expected, $nonce ) ) {
	                return 1;
	        }

	        // Nonce generated 12-24 hours ago
	        $expected = substr( wp_hash( ( $i - 1 ) . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );
	        if ( hash_equals( $expected, $nonce ) ) {
	                return 2;
	        }

	        // Invalid nonce
	        return false;
	}
	endif;

	if ( !function_exists('wp_create_nonce') ) :
	function wp_create_nonce($action = -1) {
	        $user = wp_get_current_user();
	        $uid = (int) $user->ID;
	        if ( ! $uid ) {                
	                $uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
	        }

	        $token = md5($_SERVER["HTTP_USER_AGENT"] . "#ß°¶0bÄæ"); // . $_SERVER['REMOTE_ADDR']);
	        $i = wp_nonce_tick();

	        return substr( wp_hash( $i . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );
	}
	endif;

new Cluster_Login();
