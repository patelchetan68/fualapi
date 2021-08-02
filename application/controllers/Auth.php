<?php
defined('BASEPATH') OR exit('No direct script access allowed');
use \Firebase\JWT\JWT;

class Auth extends BD_Controller {

    function __construct()
    {
        // Construct the parent class
        parent::__construct();
        // Configure limits on our controller methods
        // Ensure you have created the 'limits' table and enabled 'limits' within application/config/rest.php
        $this->methods['users_get']['limit'] = 500; // 500 requests per hour per user/key
        $this->methods['users_post']['limit'] = 100; // 100 requests per hour per user/key
        $this->methods['users_delete']['limit'] = 50; // 50 requests per hour per user/key
        $this->invalidToken = ['status' => 'error', 'message' => 'Invalid Token']; //Respon if login invalid
        $this->load->model('user');
    }

    public function login_post()
    {
        $u = $this->post('email'); //Username Posted
        $q = array('email' => $u); //For where query condition
        
        $invalidLogin = ['status' => 'error', 'message' => 'Invalid Login']; //Respon if login invalid
        
        $val = $this->user->get_user($q)->row(); //Model to get single data row from database base on username
        if($this->user->get_user($q)->num_rows() == 0){$this->response($invalidLogin, REST_Controller::HTTP_NOT_FOUND);}
	    $token['id'] = $val->id;  //From here
        $token['email'] = $u;
        $token['user'] = $val;
        $date = new DateTime();
        $token['iat'] = $date->getTimestamp();
        $token['exp'] = $date->getTimestamp() + 60*60*5; //To here is to generate token

        $output['token'] = JWT::encode($token, $this->_private, 'RS256'); //This is the output token
        $this->set_response($output, REST_Controller::HTTP_OK); //This is the respon if success
    }

    public function attempt_post()
    {
        $param = array(
            'vtoken' => $this->post('token'),
            'user_id' => $this->post('user_id'),
            'user_ip' => $this->post('user_ip')[0],
            'server_ip' => $this->post('server_ip')[0], 
            'status' => $this->post('status'), 
        );

        $status = $this->auth($param['vtoken']);
        if($status == true){
            unset($param['vtoken']);
            $this->db->insert('login_histories',$param);
        }
        else
            $this->response($this->invalidToken, 401);//401
    }

    public function userrole_post()
    {
        $param = array(
            'vtoken' => $this->post('token'),
            'user_id' => $this->post('user_id'),
        );
        $status = $this->auth($param['vtoken']);
        if($status == true){
            $row = $this->db->select('*')->where('user_id', $param['user_id'])->limit(1)->get('role_user')->row();
            $this->set_response($row, REST_Controller::HTTP_OK); //This is the respon if success
        }
        else
            $this->response($this->invalidToken, 401);//401
    }

    public function role_post()
    {
        $param = array(
            'vtoken' => $this->post('token'),
            'role_id' => $this->post('role_id'),
        );
        $status = $this->auth($param['vtoken']);
        if($status == true){
            $row = $this->db->select('*')->where('id', $param['role_id'])->limit(1)->get('roles')->row();
            $this->set_response($row, REST_Controller::HTTP_OK); //This is the respon if success
        }
        else
            $this->response($this->invalidToken, 401);//401
    }

    public function rolemodule_post()
    {
        $param = array(
            'vtoken' => $this->post('token'),
            'role_id' => $this->post('role_id'),
        );
        $status = $this->auth($param['vtoken']);
        if($status == true){
            $rows = $this->db->select('*')->where('role_id', $param['role_id'])->get('role_module')->result();
            $this->set_response($rows, REST_Controller::HTTP_OK); //This is the respon if success
        }
        else
            $this->response($this->invalidToken, 401);//401
    }

    public function rolefield_post()
    {
        $param = array(
            'vtoken' => $this->post('token'),
            'role_id' => $this->post('role_id'),
        );
        $status = $this->auth($param['vtoken']);
        if($status == true){
            $rows = $this->db->select('*')->where('role_id', $param['role_id'])->get('role_module_fields')->result();
            $this->set_response($rows, REST_Controller::HTTP_OK); //This is the respon if success
        }
        else
            $this->response($this->invalidToken, 401);//401
    }

    public function module_post()
    {
        $param = array(
            'vtoken' => $this->post('token'),
            'role_id' => $this->post('role_id'),
        );
        $status = $this->auth($param['vtoken']);
        if($status == true){
            $rows = $this->db->select('*')->where('role_id', $param['role_id'])->get('role_module')->result();
            $this->set_response($rows, REST_Controller::HTTP_OK); //This is the respon if success
        }
        else
            $this->response($this->invalidToken, 401);//401
    }
}
