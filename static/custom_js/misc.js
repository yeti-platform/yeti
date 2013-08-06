$(
function navigation_highlight() {
  page = location.pathname.split("/")[1];
  $('#'+page+"-nav").addClass('active');
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
	console.log(queries)
	querydict = {};

	for (var i in queries) {
		querydict[queries[i].split('=')[0]] = queries[i].split('=')[1];	
	}

	url = url_static_prefix + url +"?"+ $.param(querydict)

	console.log(url)

	location.href = url
}

function get_dataset(query, url, pagination_start, per_page) {
	queries = query.split(' ');
	console.log(queries)
	querydict = {};

	for (var i in queries) {
		querydict[queries[i].split('=')[0]] = queries[i].split('=')[1];	
	}

	if (pagination_start == undefined || per_page == undefined) {
		querydict['pagination_start'] = 0;
		querydict['per_page'] = 50;
	}
	else {
		querydict['pagination_start'] = pagination_start
		querydict['per_page'] = per_page
	}

	console.log(querydict)

	$.ajax({
	  dataType: "json",
	  url: url,
	  data: querydict,
	  success: function(data){
	  	dataset = $('#dataset')
	  	dataset.empty()
	  	head = $("<tr>")

	  	for (var i in data.fields) {
	  		head.append($("<th>").text(data.fields[i][1]))
	  	}
	  	head.append($("<th>").text(''))

	  	// dataset.append('<tr><th>Value</th><th>Type</th><th>Context</th><th></th></tr>')
	  	dataset.append(head)

	  	for (var i in data.elements) {
	  		//console.log(data[i])
	  		elt = data.elements[i]

	  		context_links = new Array()
	  		row = $("<tr id='row_"+elt['_id']['$oid']+"'></tr>")
	  		for (var key in data.fields) {
	  				k = data.fields[key][0]
	  				v = elt[k]
	  				if (k == 'context')
	  					row.append($("<td />").addClass('context_links'))
	  				else if (v == "")
	  					row.append($("<td />"))
	  				else
	  					row.append("<td><a href='"+url_static_prefix+"nodes/"+k+"/"+v+"'>"+v+"</a></td>")
	  		}
	  		// row.append("<td class='context_links'></td>")
	  		row.append("<td><i class='icon-remove' onclick='javascript:dataset_remove(\""+elt['_id']['$oid']+"\")'></i></td>")

	  		context_links = row.find('.context_links')

	  		for (var c in elt['context']) {
	  			a = $('<a>')
	  			a.attr('href', url_static_prefix+'nodes/context/'+elt['context'][c])
	  			a.text(elt['context'][c])
	  			if (c != 0)
	  				context_links.append(', ')
	  			context_links.append(a)
	  		}
	  		dataset.append(row)
	  	}
	  }
	});
}