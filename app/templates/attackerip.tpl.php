<div id="content">
<form method="post" action="?action=attackerip" name="<?php echo $formname;?>" id="<?php echo $formname;?>">
Search malicious IP database: <input type="text" name="ip"/> <input type="submit" value="Search"/><br/>
<input type="hidden" name="token" value="<?php echo $token;?>"/>
<input type="hidden" name="form_name" value="<?php echo $formname;?>"/>
</form>
<?php if ($ip !== "") { ?>
<p class="lead">Report for <?php echo $ip_rpt_display;?></p>
<div class="well well-small">
	<h4>Honeypot logins</h4>
	<p>This ip has attempted <span class="badge badge-info"><?php echo $login_attempts; ?></span> logins on the honeypot.</p>
</div>
<div class="well well-small">
<h4>Darknet sensors</h4>
Your search returned <?php echo count($darknet_drops);?> results from darknet sensors.
<?php 
if (count($darknet_drops) > 0) {
	echo $content;	
}
?>
</div>
<div class="well">
<h4>OSSEC alerts</h4>
<table class="table table striped">
<thead>
<tr><th>Alert date</th><th>Alert level</th><th>Log entry</th></tr>
</thead><tbody>
<?php
foreach ($ossec_alerts as $alert) {
	echo "<tr><td>" . $alert->alert_date . "</td>";
	echo "<td>" . $alert->rule_level . "</td>";
	echo "<td>" . htmlspecialchars($alert->rule_log) . "</td></tr>\n";
}
?>
</tbody>
</table>
</div>
<?php } ?>
</div>