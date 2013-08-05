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

function get_dataset(query, url) {
	queries = query.split(' ');
	console.log(queries)
	querydict = {};
	for (var i in queries) {
		querydict[queries[i].split('=')[0]] = queries[i].split('=')[1];	
	}

	console.log(querydict)


	$.ajax({
	  dataType: "json",
	  url: url,
	  data: querydict,
	  success: function(data){
	  	dataset = $('#dataset')
	  	dataset.empty()
	  	dataset.append('<tr><th>Value</th><th>Type</th><th>Context</th><th></th></tr>')

	  	for (var i in data) {
	  		//console.log(data[i])
	  		elt = data[i]

	  		context_links = new Array()
	  		
	  		row = $("<tr id='row_"+elt['_id']['$oid']+"'><td><a href='"+url_static_prefix+"nodes/value/"+elt['value']+"'>"+elt['value']+"</a></td><td><a href='"+url_static_prefix+"nodes/type/"+elt['type']+"'>"+elt['type']+"</a></td><td class='context_links'></td><td><i class='icon-remove' onclick='javascript:dataset_remove(\""+elt['_id']['$oid']+"\")'></i></td></tr>")

	  		context_links = row.find('.context_links')

	  		for (var c in elt['context']) {
	  			a = $('<a>')
	  			a.attr('href',url_static_prefix+'nodes/context/'+elt['context'][c])
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