<?php defined('BASEPATH') OR exit('No direct script access allowed');

// This can be removed if you use __autoload() in config.php OR use Modular Extensions
/** @noinspection PhpIncludeInspection */
require_once APPPATH . '/libraries/REST_Controller.php';
require_once APPPATH . '/libraries/JWT.php';
require_once APPPATH . '/libraries/BeforeValidException.php';
require_once APPPATH . '/libraries/ExpiredException.php';
require_once APPPATH . '/libraries/SignatureInvalidException.php';
use \Firebase\JWT\JWT;

class BD_Controller extends REST_Controller
{
    function __construct() {
        parent::__construct();

        $this->_clspath = $this->router->fetch_directory();
        $this->_class   = $this->router->fetch_class();
        $this->_upload  = 'upload';
        $this->_method  = $this->router->fetch_method();
        $this->_uri     = $this->uri->segment_array();

        $this->load->helper('inflector');
        $this->_table      = plural($this->_class);
        $this->_fields     = array('id', 'name');
        $this->_orderby    = 'id';
        $this->_search     = ['name'];
        $this->_javascript = '';

        $this->_private = $this->config->item('private_key');
        $this->_public = $this->config->item('public_key');
    
    }
    private $user_credential;
    public function auth($token)
    {
        // Configure limits on our controller methods
        // Ensure you have created the 'limits' table and enabled 'limits' within application/config/rest.php
        $this->methods['users_get']['limit'] = 500; // 500 requests per hour per user/key
        $this->methods['users_post']['limit'] = 100; // 100 requests per hour per user/key
        $this->methods['users_delete']['limit'] = 50; // 50 requests per hour per user/key
        //JWT Auth middleware

        $headers = $this->input->get_request_header('Authorization');
        if (!empty($headers)) {
        	if (preg_match('/Bearer\s(\S+)/', $headers , $matches)) {
                $token = $matches[1];
        	}
    	}
        try {
           $decoded = JWT::decode($token, $this->_public, array('RS256'));
           $this->user_data = $decoded;
           return true;
        } catch (Exception $e) {
           return false; //Respon if credential invalid
           //$this->response($invalid, 401);//401
        }
    }
}