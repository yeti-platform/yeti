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
		 document.location.href='/dataset/clear';
		  }
}

function dataset_remove(id) {
	$.ajax({
		dataType: "json",
		url: '/dataset/remove/'+id,
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
	  	
	  		context = elt['context'].join(", ")
	  		dataset.append("<tr id='row_"+elt['_id']['$oid']+"'><td><a href='"+elt['link_value']+"'>"+elt[elt['type']]+"</a></td><td><a href='"+elt['link_type']+"'>"+elt['type']+"</a></td><td>"+context+"</td><td><i class='icon-remove' onclick='javascript:dataset_remove(\""+elt['_id']['$oid']+"\")'></i></td></tr>")
	  	}
	  }
	});
	// $.getJSON(url, querydict, function(data) {
	// 	console.log(data)
	// })

	// var jqxhr = $.getJSON(url, function() {
	//   console.log( "success" );
	// })
	// .done(function() { console.log( "second success" ); })
	// .fail(function(jqXHR, textStatus, errorThrown) { 
	// 	console.log( jqXHR);
	// 	console.log( textStatus);
	// 	console.log( errorThrown); 
	// })
	// .always(function() { console.log( "complete" ); });
	 
}