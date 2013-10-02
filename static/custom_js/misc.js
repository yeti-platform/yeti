$(
	function navigation_highlight() {
	  section = location.href.split(url_static_prefix)[1].split('/')[0];
	  $('#'+section+"-nav").addClass('active');
	}
)

function clear_db() {
	var r=confirm("You sure?");
	if (r==true)
	  {
	 	document.location.href=url_static_prefix+'dataset/clear';
	  }
}

function dataset_remove(id) {
	$.ajax({
		dataType: "json",
		url: url_static_prefix+'dataset/remove/'+id,
		success:function(data){
			if (data['n'] == 1)
				$('#row_'+id).remove()
			else
				console.log("Could not remove element "+id)
		}
	});
}

function get_dataset_csv(query, url) {
	queries = query.split(' ');
	querydict = {};

	for (var i in queries) {
		splitted = queries[i].split('=')
		if (splitted.length > 1)
			querydict[splitted[0]] = splitted[1];	
		else if (splitted[0] != "")
			querydict['value'] = splitted[0]
	}


	url = url_static_prefix + url +"?"+ $.param(querydict)
	
	location.href = url
}

function change_page(arg, url) {
	console.log('loading page ' + arg)
	query = $('#query').val()
	location.hash = arg
	get_dataset(query, url)
}

function get_dataset(query, url) {

	queries = query.split(' ');
	querydict = {};

	for (var i in queries) {
		splitted = queries[i].split('=')
		if (splitted.length > 1)
			querydict[splitted[0]] = splitted[1];	
		else if (splitted[0] != "")
			querydict['value'] = splitted[0]
	}

	// un # dans l'url
	page = location.hash.split("#")[1]

	if (page == undefined) {
		page = 0;
	}

	querydict['page'] = page

	querydict['fuzzy'] = $('#fuzzy').prop('checked')

	$.ajax({
	  dataType: "json",
	  url: url,
	  data: querydict,
	  beforeSend: function(data) {
	  	$('#loading-spinner').addClass('show')
	  },
	  complete: function(data) {
	  	$('#loading-spinner').removeClass('show')
	  },
	  success: function(data){
	  	// empty the table and populate it 
	  	dataset = $('#dataset')
	  	dataset.empty()
	  	head = $("<tr>")

	  	// get the headers
	  	for (var i in data.fields) {
	  		h = $("<th>").text(data.fields[i][1])
	  		if (data.fields[i][0].indexOf('date') != -1)
	  			h.addClass('timestamp')
	  		head.append(h)
	  	}

	  	head.append($("<th>").text(''))

	  	dataset.append(head)

	  	// loop over the elements

	  	for (var i in data.elements) {
	  		elt = data.elements[i]
	  		tags_links = new Array()
	  		//create row
	  		row = $("<tr id='row_"+elt['_id']['$oid']+"'></tr>")
	  		for (var key in data.fields) {
	  				k = data.fields[key][0]
	  				v = elt[k]
	  				if (k == 'tags')
	  					row.append($("<td />").addClass('tags_links'))
	  				else if (k.indexOf('date') != -1)
	  					row.append($("<td />").text(format_date(new Date(elt.date_updated.$date))).addClass('timestamp'))
	  				else if (v == "" || v == undefined)
	  					row.append($("<td />").text('-'))
	  				else
	  					row.append("<td><a href='"+url_static_prefix+"nodes/"+k+"/"+v+"'>"+v+"</a></td>")
	  		}

	  		row.append("<td><i class='icon-remove' onclick='javascript:dataset_remove(\""+elt['_id']['$oid']+"\")'></i></td>")

	  		tags_links = row.find('.tags_links')

	  		for (var c in elt['tags']) {
	  			a = $('<a>')
	  			a.attr('href', url_static_prefix+'nodes/tags/'+elt['tags'][c])
	  			a.text(elt['tags'][c])
	  			if (c != 0)
	  				tags_links.append(', ')
	  			tags_links.append(a)
	  		}

	  		// append the created row to the table
	  		dataset.append(row)
	  	}

	  	// adjust pagination
	  	per_page = 50;
	  	total_pages = Math.floor(data.total_results / per_page)
	  	previous_page = page - 1 >= 0 ? page - 1 : 0;
	  	next_page = (page*1+1) <= total_pages ? page*1 + 1 : page*1;
	  	
	  	prev = $("#pagination-prev")
	  	next = $("#pagination-next")
	  	$("#pagination-page").text("Page "+page+" of "+ total_pages)
	  	$("#total-results").text(data.total_results)
	  	
	  	prev.attr('data-nav', previous_page)
	  	next.attr('data-nav', next_page)
	  }
	});
}