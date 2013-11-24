
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
	console.log(d)
	$('#node_info').empty();
	$(".whois").empty();

	display_generic(d);
}

function display_generic(d) {
	console.log('display generic')
	if (d.fields != undefined) {
		for (var display in d.fields) {
			key = d.fields[display][0]
			label = d.fields[display][1]
			if (d[key] == undefined)
				value = "N/A"
			else {
				value = d[key]
				
				if (['date_updated', 'date_created', 'last_analysis'].indexOf(key) != -1)
					value = format_date(new Date(value.$date))
				if (key == 'tags')
					if (d.tags.length == 0) 
						value = '-'
					else
						value = d.tags.join(', ')
			}

			$("#node_info").append("<tr><th>"+label+"</th><td>"+value+"</td></tr>");	
		}
	}
	else {
		for (var key in d) {
			if (['fixed', 'selected', 'previouslyselected', 'type', 'tags', 'date_created', 'date_retreived', 'date_updated', 'last_analysis', "_id", "group", "incoming_links", "index", "px", "py", "x", "y", "radius", 'weight'].indexOf(key.toLowerCase()) == -1) {
				val = d[key]
				if (val == undefined) { val = "N/A"}
				$("#node_info").append("<tr><th>"+key.charAt(0).toUpperCase() + key.slice(1) +"</th><td>"+val+"</td></tr>");
			}
		}
	}
}


function format_date(date)
{
	// hours part from the timestamp
	var hours = date.getHours() < 10 ? '0' + date.getHours() : date.getHours();
	// minutes part from the timestamp
	var minutes = date.getMinutes() < 10 ? '0' + date.getMinutes() : date.getMinutes()
	// seconds part from the timestamp
	var seconds = date.getSeconds() < 10 ? '0' + date.getSeconds() : date.getSeconds()

	var day = date.getDate() < 10 ? '0' + date.getDate() : date.getDate()
	var month = date.getMonth()+1 < 10 ? '0' + (date.getMonth()+1) : (date.getMonth()+1)
	var year = date.getFullYear();

	// will display time in 10:30:23 format
	var formattedTime = year+"-"+month+"-"+day +" ("+hours + ':' + minutes + ':' + seconds+")";

	return formattedTime;
}