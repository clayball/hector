<p class="lead"><?php echo $count;?> Hosts Tracked</p>

<div id="addHostsModal" class="modal hide fade" aria-hidden="true">
<div class="modal-header">
<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
<h3>No hosts tracked</h3>
</div>
<div class="modal-body">
<p>You currently have no hosts tracked in the database.</p>
</div>
<div class="modal-footer">
<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
<a href="?action=add_hosts" class="btn btn-primary">Go to add hosts</a>
</div>
</div>

<div id="addScriptModal" class="modal hide fade" aria-hidden="true">
<div class="modal-header">
<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
<h3>No scripts</h3>
</div>
<div class="modal-body">
<p>You currently do not have any scanning scripts configured.  Scan scripts are required 
to perform automated scans of hosts.</p>
</div>
<div class="modal-footer">
<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
<a href="?action=config&object=scan_type" class="btn btn-primary">Go to script configuration</a>
</div>
</div>

<div id="addScanModal" class="modal hide fade" aria-hidden="true">
<div class="modal-header">
<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
<h3>No scheduled scans</h3>
</div>
<div class="modal-body">
<p>You currently do not have any scripts scheduled or scans configured.</p>
</div>
<div class="modal-footer">
<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
<a href="?action=config&object=scan" class="btn btn-primary">Go to scan schedule</a>
</div>
</div>


<div class="row">
  <div class="span6">
  	<h3>Scanner:  Top Ports Detected</h3>
  	<div id="portSummaryChartLabels" class="hidden"><?php echo $portSummaryLabels;?></div>
  	<div id="portSummaryChartData" class="hidden"><?php echo $portSummaryCounts;?></div>
	<canvas id="topPortsChart" width="400"></canvas>
    
  </div>
  
  <div class="span6">
	<h3>Darknet:  Top Port Probes in Last 4 Days</h3>
	<canvas id="darknetChart"  width="400"></canvas>
	<div id="darknetSummaryChartLabels" class="hidden"><?php echo $darknetSummaryLabels;?></div>
  	<div id="darknetSummaryChartData" class="hidden"><?php echo $darknetSummaryCounts;?></div>
	</div>
</div>

<div class="row">
    <!-- Incident Pie Chart -->
    <div class="span6"> 
        <div id="incident-div">
            <div id="incidentReportHeader" class="hidden"><?php echo $incident_report_header?></div>
            <div id="incidentChartLabels" class="hidden"><?php echo $incidentchart_labels?></div>
            <div id="incidentChartCounts" class="hidden"><?php echo $incidentchart_counts?></div>
            <h3 id="incidentChartHeader"></h3>
            <canvas id="incidentChart"></canvas>
            <div id="incidentChartLegend"></div>
        </div>
    </div>
    
    <div class="span6">
    <h3>Darknet:  Probes in Last 4 Days by Country</h3>
    <figure><div id="world-map-gdp" style="height:300px;"></div>
    <script>
    <?php
    foreach ($darknetmapcounts as $key=>$val) {
    	?>
        countryData['<?php echo $key;?>']=<?php echo $val;?>;
        <?php
    }
    ?>
    //@code_start
    $(function(){
    $('#world-map-gdp').vectorMap({
        map: 'world_mill_en',
        series: {
            regions: [{
                values: countryData,
                scale: ['#C8EEFF', '#0071A4'],
                normalizeFunction: 'polynomial'
            }]
        },
        onRegionLabelShow: function(event, label, code){
            label.html(
                '<b>'+label.html()+'</b></br>'+countryData[code]+ ' probes'
            );
        },
        onRegionClick: function (event, code) {
            location.href = "?action=darknetsummary&country="+code;
        }
        });
      });
      //@code_end
    </script></figure>
    </div>

</div>

<div class="row">
    <div class="span6">
    <!-- Kojoney Login Attempts Map -->
    <h3>Kojoney: Login Attempts in Last 4 Days by Country</h3>
		<div id="kojoney-map-counts" class="hidden"><?php echo $kojoneymapcounts ?></div>
		<div id="kojoney-worldmap" style="height:300px;"></div>
    </div>
  
    <div class="span6">
        <h3>Timeline of Probes</h3>
        <canvas id="darknetCountryChart" height="300"></canvas>
        <script>
        $(document).ready(function(){
            //var displayLabels = document.getElementById('darknetSummaryChartLabels').textContent.split(",");
            //var dataPoints = document.getElementById('darknetSummaryChartData').textContent.split(",");
        
            var data = {
                labels : [<?php print "'" . implode("','", $datelabels) . "'";?>],
                datasets : [ 
<?php 
                        $colors = array("220,220,220", 
                                        "151,187,205", 
                                        "121,187,105", 
                                        "131,187,205", 
                                        "179,107,205", 
                                        "101,27,205", 
                                        "251,207,205", 
                                        "51,150,205", 
                                        "101,113,205", 
                                        "205,190,205", 
                                        "63,135,205");
                        $x = 0;
                        foreach ($countrycountdates as $country_code=>$countarray) {
                        	print "\t\t\t\t\t{\n";
                            print "\t\t\t\t\t\tlabel: \"" . $country_code . "\",\n";
                            print "\t\t\t\t\t\ttitle: \"" . $country_code . "\",\n";
                            print "\t\t\t\t\t\tfillColor : \"rgba(".$colors[$x].",0.2)\",\n";
                            print "\t\t\t\t\t\tstrokeColor : \"rgba(".$colors[$x].",1)\",\n";
                            print "\t\t\t\t\t\tpointColor : \"rgba(".$colors[$x].",1)\",\n";
                            print "\t\t\t\t\t\tpointStrokeColor: \"#fff\",\n";
                            print "\t\t\t\t\t\tpointHighlightFill: \"#fff\",\n";
                            print "\t\t\t\t\t\tpointHighlightStroke : \"rgba(".$colors[$x].",1)\",\n";
                            print "\t\t\t\t\t\tdata : [" . implode(",", $countarray) . "]\n";
                            print "\t\t\t\t\t},\n";
                            $x++;
                        }
?>
                ]
            };
            var options = {
            	bezierCurve: true,
                multiTooltipTemplate: "<%= datasetLabel%> - <%= value %>",
            };
            var myNewChart = new Chart(document.getElementById("darknetCountryChart").getContext("2d")).Line(data, options);
            $("#darknetCountryChart").hover(function (evt) {
                var activeBars = myNewChart.getPointsAtEvent(evt);
                console.log(activeBars);
            });        
        });
        </script>
    </div>
</div>