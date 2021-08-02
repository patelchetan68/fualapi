<?php if(!defined('BASEPATH')) exit('No direct script allowed');

class User extends CI_Model{

	function get_user($q = null) {
		return $this->db->get_where('users',$q);
	}

	
}