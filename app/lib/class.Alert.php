<?php
/**
 * HECTOR - class.Alert.php
 *
 * This file is part of HECTOR.
 *
 * @author Justin C. Klein Keane <jukeane@sas.upenn.edu>
 * @package HECTOR
 */

/**
 *  Set up error reporting 
 */
error_reporting(E_ALL);

if (0 > version_compare(PHP_VERSION, '5')) {
    die('This file was generated for PHP 5');
}


/* user defined includes */
require_once('class.Config.php');
require_once('class.Db.php');
require_once('class.Log.php');
require_once('class.Collection.php');
require_once('class.Host.php');


/**
 * Alert class is the object for port change alert messages.
 * Alerts hold the contents of Alert messages generated by
 * nmap scans, in the form:
 * 
 * Port 22 changed from filtered to open on 130.91.128.192
 *
 * @access public
 * @author Justin C. Klein Keane <jukeane@sas.upenn.edu>
 * @package HECTOR
 */
class Alert {

    // --- ATTRIBUTES ---
    
    /**
     * String of the Alert message, in the form:
     * 
     * Port 22 changed from filtered to open on 130.91.128.192
     *
     * @access private
     * @var String The alert message
     */
    private $string = null;
    
    /**
     * Unique id from the database
     * 
     * @access private
     * @var Int The unique id
     */
    private $id = null;
  
    /**
     * The timestamp of the alert
     * 
     * @access private
     * @var Timestamp The timestamp of the alert
     */
	private $timestamp = null;
    
    /**
     * The ID of the host associated with this alert.
     * 
     * @access private
     * @var Int The unique id of the Host for this alert
     */
    private $host_id = null;

    /**
     * Constructor to either create a new shell Alert or
     * call an existing Alert fromt he database
     *
     * @access public
     * @author Justin C. Klein Keane <jukeane@sas.upenn.edu>
     * @param  Int The unique id from the database
     * @return void
     */
    public function __construct($id = '') {
        $this->db = Db::get_instance();
		$this->log = Log::get_instance();
		if ($id != '') {
			$sql = array(
				'SELECT * FROM alert WHERE alert_id = ?i',
				$id
			);
			$result = $this->db->fetch_object_array($sql);
			if (is_array($result) && isset($result[0])) {
				$this->set_id($result[0]->alert_id);
				$this->set_string($result[0]->alert_string);
				$this->set_timestamp($result[0]->alert_timestamp);
				$this->set_host_id($result[0]->host_id);	
			}
		}
    }

    /**
     * Delete the record from the database
     *
     * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @return Boolean True if the delete succeeds, False otherwise.
     */
    public function delete() {
    	if ($this->id > 0 ) {
    		// Delete an existing record
	    	$sql = array(
	    		'DELETE FROM alert WHERE alert_id = \'?i\'',
	    		$this->get_id()
	    	);
	    	$retval = $this->db->iud_sql($sql);
    	}
    	$this->set_id(null);
    	return false;
    }
    
    /**
     * Get collection definition by date range or IP
     * 
     * @access public
     * @author Justin C. Klein Keane <jukeane@sas.upenn.edu>
     * @param Array An associative array('startdate'=>date, 'enddate'=>date, 'ip'=>ip)
     * @return String The SQL string to select items
     */
    public function get_collection_by_dates_ip($filter, $orderby='') {
        $startdate='0000-00-00';
        $enddate='';
        $ip='0.0.0.0';
        $limit = '';
        if (is_array($filter)) {
        	if (isset($filter['startdate'])) $startdate = $filter['startdate'];
            if (isset($filter['enddate'])) $enddate = $filter['enddate'];
            if (isset($filter['ip'])) $ip = $filter['ip'];
        }
        $startdate = ($startdate !== '0000-00-00') ? mysql_real_escape_string(date('Y-m-d', strtotime($startdate))) : '0000-00-00';
    	if ($startdate !== '0000-00-00') {
            $limit .= ' AND a.alert_timestamp >= "' . $startdate . '" ';
        }
        // Validate the endtime and add it to the string
        $enddate = ($enddate !== '') ? mysql_real_escape_string(date('Y-m-d', strtotime($enddate))) : '';
        if ($enddate !== '') {
            $limit .= ' AND a.alert_timestamp <= "' . $enddate . ' 23:59:59" ';
        }
        
        // Validate the IP and add it to the query
        if ($ip !== '0.0.0.0' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $ip = mysql_real_escape_string($ip);
            $limit .= ' AND h.host_ip_numeric = inet_aton("' . $ip . '") ';
        }
        
        
        $sql = 'SELECT a.alert_id ' .
            'FROM alert a, host h ' .
            'WHERE a.host_id = h.host_id ' .
            $limit . 
            ' ORDER BY a.alert_timestamp DESC ' .
            ' LIMIT 200'; 
        return $sql;
    }
    
    /** 
     * This function directly supports the Collection class.
	 * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
	 * @return SQL select string
	 * @param String Filter for the SQL WHERE clause
	 * @param String Optional ORDER BY clause for SQL
	 */
	public function get_collection_definition($filter = '', $orderby = ' ORDER BY alert_timestamp DESC') {
		$query_args = array();
		$sql = 'SELECT alert_id FROM alert WHERE alert_id > 0';
		if ($filter != '' && is_array($filter))  {
			$sql .= ' ' . array_shift($filter);
			$sql = $this->db->parse_query(array($sql, $filter));
		}
		if ($filter != '' && ! is_array($filter))  {
			$sql .= ' ' . $filter . ' ';
		} 
		if ($orderby != '') {
			$sql .= ' ' . $orderby;
		}
		return $sql;
	}
	
	/**
	 * Get the generic displays for templates
	 * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
	 * @return Array An array of display fields and lookup methods
	 */
	public function get_displays() {
		return array('Timestamp'=>'get_timestamp', 'Alert'=>'get_string', 'Host'=>'get_host_linked');
	}

	/**
	 * Get an HTML link to the host details page
	 * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
	 * @return String An HTML link to the host details page.
	 */
	public function get_host_linked() {
		$host = new Host($this->get_host_id());
		$retval = '<a href="?action=host_details&object=host&id=' . 
				$this->get_host_id() . '">' .
				$host->get_name() . '</a>';
		return $retval;
	}
	
	/**
	 * Return the unique ID for the host associated with this object
	 * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
	 * @return Int The unique id for the host
	 */
	public function get_host_id() {
		return intval($this->host_id);
	}
	
	/**
	 * Get the name of the host as the last entry in the message string
	 * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
	 * @return String The last element of the string, which should be the IP of the host.
	 */
	public function get_host() {
    	$string = $this->get_string();
    	$splitstring = explode(' ', $string);
    	return $splitstring[ count($splitstring) - 1 ];
	}

    /**
     * Return the unique id from the data layer
     *
     * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @return Int The unique id from the data layer.
     */
    public function get_id() {
        return (int) $this->id;
    } 
    
    /**
     * Get the second element of the message, which should be the port
     * 
     * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @return String The port whose state changed.
     */
    public function get_port() {
    	$string = $this->get_string();
    	$splitstring = explode(' ', $string);
    	return $splitstring[1];
    }

    /**
     * Retrieve the alert message string.
     *
     * @access public
     * @author Justin C. Klein Keane <jukeane@sas.upenn.edu>
     * @return String The message string for this alert, sanitized for HTML.
     */
    public function get_string() {
    	return htmlspecialchars($this->string);
    }
    
    /**
     * Get the timestamp of this alert
     * 
     * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @return Timestamp The output safe timestamp for this alert.
     */
    public function get_timestamp() {
    	return htmlspecialchars($this->timestamp);
    }
    
    /**
     * Persist the object to the data layer. On the save of 
     * a new record the id parameter is populated.
     * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @return Boolean True if the save worked properly, false otherwise.
     */
    public function save() {
    	if (($this->host_id == NULL) || ($this->string == NULL)) return false;
    	$sql = '';
    	if ($this->id == NULL) {
    		$sql = array('INSERT INTO alert (alert_timestamp, alert_string, host_id) ' .
    			' values (NOW(), \'?s\', ?i)',
    			$this->string,
    			$this->host_id);
    		$retval = $this->db->iud_sql($sql);
	    	// Now set the id
	    	$sql = 'SELECT LAST_INSERT_ID() AS last_id';
	    	$result = $this->db->fetch_object_array($sql);
	    	if (isset($result[0]) && $result[0]->last_id > 0) {
	    		$this->set_id($result[0]->last_id);
	    	}
    	}
    	else {
    		$sql = array('UPDATE alert set alert_timestamp = \'?d\', alert_string = \'?s\', host_id = ?i ' .
    			' where alert_id = ?d',
    			$this->timestamp,
    			$this->string,
    			$this->host_id,
    			$this->id);
    		$retval = $this->db->iud_sql($sql);
    	}
    	return $retval;
    }
    
    /**
     * Set the ID for the Host associated with this alert.
     * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @param Int The Host id for this Alert
     * @return void
     */
    public function set_host_id($id) {
    	$this->host_id = intval($id);
    }
	
    /**
     * Set the object's unique id
     *
     * @access protected
     * @author Justin C. Klein Keane <jukeane@sas.upenn.edu>
     * @param  int The unique id for hte object
     * @return void
     */
    protected function set_id($id) {
       $this->id = (int) $id;
    }
    
    /**
     * Set the Alert message string
     * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @param String The message string.
     */
    public function set_string($string) {
    	$this->string = $string;
    }
    
    /**
     * Set the Alert timestamp
     * 
	 * @access public
     * @author Justin C. Klein Keane, <jukeane@sas.upenn.edu>
     * @param Timestamp The timestamp for the alert
     */
    public function set_timestamp($stamp) {
    	$this->timestamp = $stamp;
    }
    

} /* end of class Alert */

?> 