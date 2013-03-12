<?php
/**
 * HECTOR - mail_alerts.php
 *
 * This file is part of HECTOR.
 *
 * @author Justin C. Klein Keane <jukeane@sas.upenn.edu>
 * @package HECTOR
 */
 
/**
 * Defined vars
 */
if(php_sapi_name() == 'cli') {
	$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	$approot = '/opt/hector/app/';
}
else {
	$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	$approot = realpath(substr($_SERVER['PATH_TRANSLATED'],0,strrpos($_SERVER['PATH_TRANSLATED'],'/')) . '/../') . '/';
}

	
	
/**
 * Neccesary includes
 */
require_once($approot . 'lib/class.Config.php');
require_once($approot . 'lib/class.Host.php');
require_once($approot . 'lib/class.Alert.php');

/**
 * Singletons
 */
new Config();
$db = Db::get_instance();

function mail_alerts($testing='No') {
	/**
	 * Send out notices of new ports observed
	 */
	
	$filter = ' AND host_id NOT IN (select h.host_id from host h ' .
			'	where TO_DAYS(h.host_ignored_timestamp) + h.host_ignoredfor_days > TO_DAYS(now())) ';
	$filter .= ' ORDER BY alert_timestamp DESC';
	// Use today (should report at end of scan)
	$today  = mktime(0, 0, 0, date("m")  , date("d"), date("Y"));
	$timestart = date("Y-m-d 00:00:00", $today);
	
	$datelimit = 'AND alert_timestamp >= \'' . $timestart . '\'';
	$collection = new Collection('Alert', ' AND alert_string LIKE \'%to open%\' ' . $datelimit, '', $filter);
	$alerts = $collection->members;
	$output = "Newly observed ports:\n\n";
	$htmloutput = "<h4>Newly observed ports:</h4>";
	if (isset($alerts) && is_array($alerts)) {
		$host = '';
		foreach ($alerts as $alert) {
			$tmphost = $alert->get_host();
			if ($host == $tmphost) {
				$output .= "\t\t" . $alert->get_port() . "\n";
				$htmloutput .= "<li>" . $alert->get_port() . "</li>";
			}
			else {
				if ($host !== '') $htmloutput .= "</ul>";
				$host = $tmphost;
				$output .= $host . " at " . $alert->get_timestamp() . "\n";
				$output .= "\tNew Ports:\n";
				$output .= "\t----------\n";
				$output .= "\t" . $alert->get_port() . " (" . getservbyport($alert->get_port(), 'tcp') . ")\n";
				
				
				$htmloutput .= "<strong>" . $host . " at " . $alert->get_timestamp() . "</strong><br/>";
				$htmloutput .= "New Ports:";
				$htmloutput .= "<ul>";
				$htmloutput .= "<li>" . $alert->get_port() . " (" . getservbyport($alert->get_port(), 'tcp') . ")</li>";
			}
		}
	}
	$to      = $_SESSION['site_email'];
	$subject = 'New Ports Observed Today';
	$boundary_hash = md5('HECTOR OSInt Platform');
	$plain_heading = "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"iso-8859-1\"\r\nContent-Transfer-Encoding: 7bit\r\n";
	$html_heading = str_replace('plain', 'html', $plain_heading);
	$message = "--PHP-alt-" . $boundary_hash . "\r\n" . $plain_heading . $output . 
			"\r\n\r\n" . "--PHP-alt-" . $boundary_hash . $html_heading .
			"\r\n" . $htmloutput;
	$headers = 'From: ' . $_SESSION['site_email'] . "\r\n" .
	    'Reply-To: ' . $_SESSION['site_email'] . "\r\n" .
	    'Content-Type: multipart/alternative; boundary="PHP-alt-' . $boundary_hash . '"' . "\r\n";
	    'X-Mailer: HECTOR';
	
	if ($message != '') mail($to, $subject, $message, $headers);
	
	// Send alerts to Supprot groups about machines observed in their area
	if ($testing !== 'No') {
		/*$lspgColl = new Collection('Supportgroup' , " AND supportgroup_email IS NOT NULL AND supportgroup_email != ''");
		$groups = $lspgColl->members;
		if (isset($groups) && is_array($groups)) {
			foreach ($groups as $group) {
				$hosts = $group->get_host_ids();
				$hosts = implode(",", $hosts);
				$filter_string = ' AND alert_string LIKE \'%to open%\' ';
				$filter_string .= $datelimit . ' and host_id IN (' . $hosts . ')';
				$collection = new Collection('Alert', $filter_string , '', $filter);
				$alerts = $collection->members;
				$output = "";
				if (isset($alerts) && is_array($alerts)) {
					foreach ($alerts as $alert) {
						
						$output .= '[' . $alert->get_timestamp() . 
							'] ' . $alert->get_string();
						$output .=  "\n";
					}
				}
				if ($output != '') {
					$to = $group->get_email();
					$footer = "\r\n\r\nYou are receiving this e-mail as part of the nightly HECTOR port scan.\r\n" .
						"You can log in to HECTOR to review these results at " . $_SESSION['site_url'] . "\r\n\r\n" .
						"If you feel you are getting these alerts in error or if you have any questions about response " .
						"or remediation please contact " . $_SESSION['site_email'];
					$message = $output . $footer;
					mail($to, $subject, $message, $headers);
				}
			}
		}*/
	}
	syslog(LOG_INFO, 'scan_cron.php email notices complete.');
}

if(php_sapi_name() == 'cli') {
	if ($argc > 1 && $argv[1] == 'test') {
		mail_alerts('testing');
	}	
}
?>