function hide_sniffer_nodes(selected_nodes) {

}


function highlight_query(query) {

	query = query.trim()

	if (query == 'clear') {
		node.classed('dim', false)
		link.classed('dim', false)
		path_text.classed('dim', false)
		return
	}

	node.classed('dim', true)
	link.classed('dim', true)
	path_text.classed('dim', true)

	if (query.search(':') != -1) {
		args = query.split(':')
		query = "(d." + args[0] + ".search('"+args[1]+"') != -1)"
	}
	else {
		query = "(d.value.search('"+query+"') != -1)"

	}

	change_opacity(query)

}

function change_opacity(query) {

	console.log(query)
	
	ids = []
	
	hl = node.filter(function (d, i) { 
				if (eval(query)) {
					ids.push(d._id.$oid)
					return true;
				}
				else
					return false;
			})
			.classed('dim', false)[0]

	other_ids = []

	hl = link.filter(function (d, i) {
				if ((ids.indexOf(d.src.$oid) != -1) || (ids.indexOf(d.dst.$oid) != -1)) {
					other_ids.push(d.src.$oid)
					other_ids.push(d.dst.$oid)
					return true
				}
			})
			.classed('dim', false)[0]

	node.filter(function (d, i) {
		if (other_ids.indexOf(d._id.$oid) != -1)
			return true
		else
			return false
	}).classed('dim', false)
}



function display_data(d)
{

	// console.log(d)
	$('#node_info').empty();
	$(".whois").empty();

	$('#node_info').append("<tr><th>Node type</th><td>"+d.type+"</td></tr>");

	if (d.type == 'url')
		display_data_url(d);
	if (d.type == 'as')
		display_data_as(d);
	if (d.type == 'ip')
		display_data_ip(d);
	if (d.type == 'hostname')
		display_data_hostname(d);

	$('#node_info').append("<tr><th>Date Updated</th><td>"+format_date(new Date(d.date_updated.$date))+"</td></tr>");
	$('#node_info').append("<tr><th>Date Created</th><td>"+format_date(new Date(d.date_updated.$date))+"</td></tr>");
	$('#node_info').append("<tr><th>Last analysis</th><td>"+format_date(new Date(d.last_analysis.$date))+"</td></tr>");

	context_string = d.context[0];
	for (var i = 1; i < d.context.length; i++)
		context_string = context_string + ", " + d.context[i];

	$('#node_info').append("<tr><th>Context</th><td>"+context_string+"</td></tr>");

}

function display_data_hostname(d) {

	$('#node_info').append("<tr><th>Hostname</th><td>"+d.value+"</td></tr>");
	if (d.domain != null)
		$('#node_info').append("<tr><th>Domain</th><td>"+d.domain+"</td></tr>");
	if (!jQuery.isEmptyObject(d.dns_info)) {
		for (var i in d.dns_info)
			$('#node_info').append("<tr><th>"+i+"</th><td>"+d.dns_info[i]+"</td></tr>");
	}

	$('.whois').html('<small>'+d.whois.replace(/\n/g, "<br />")+'</small>');
	console.log(d.whois)
}

function display_data_url(d) {
	
	$('#node_info').append("<tr><th>URL</th><td>"+d.value+"</td></tr>");
	$('#node_info').append("<tr><th>Hostname</th><td>"+d.hostname+"</td></tr>");
}

function display_data_as(d){
	$('#node_info').append("<tr><th>AS name</th><td>"+d.as_name+"</td></tr>");
	$('#node_info').append("<tr><th>ASN</th><td> AS"+d.value+"</td></tr>");
	$('#node_info').append("<tr><th>Netblock</th><td>"+d.bgp+"</td></tr>");
	$('#node_info').append("<tr><th>Country</th><td>"+d.country+"</td></tr>");
	$('#node_info').append("<tr><th>Registry</th><td>"+d.registry+"</td></tr>");
	$('#node_info').append("<tr><th>Allocated</th><td>"+format_date(new Date(d.allocated.$date))+"</td></tr>");

}

function display_data_ip(d) {
	$('#node_info').append("<tr><th>IP</th><td>"+d.value+"</td></tr>");
	
	if (d.geoinfo) {
		geoloc_string = "";
		if (d.geoinfo.city != "")
			geoloc_string += d.geoinfo.city + ", ";
		geoloc_string += d.geoinfo.country_name +" ("+d.geoinfo.latitude+", "+d.geoinfo.longitude+")";
		$('#node_info').append("<tr><th>Geoloc</th><td>"+geoloc_string+"</td></tr>");
	}
	
	$('.whois').text(d.whois);
}

function format_date(date)
{
	// hours part from the timestamp
	var hours = date.getHours();
	// minutes part from the timestamp
	var minutes = date.getMinutes();
	// seconds part from the timestamp
	var seconds = date.getSeconds();

	var day = date.getDate();
	var month = date.getMonth()+1;
	var year = date.getFullYear();

	// will display time in 10:30:23 format
	var formattedTime = year+"-"+month+"-"+day +" ("+hours + ':' + minutes + ':' + seconds+")";

	return formattedTime;
}