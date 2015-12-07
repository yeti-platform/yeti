$(function(){

  refresh_table("");

  $("#observable-filter").keydown(function (event) {

		if (event.which == 13) {
			event.preventDefault();
			refresh_table($('#observable-filter').val());
		}
	});

});


function refresh_table(filter) {

  queries = filter.split(' ');
	filter = {};

  for (var i in queries) {
		splitted = queries[i].split('=')
		if (splitted.length > 1)
			filter[splitted[0]] = splitted[1];
		else if (splitted[0] != "")
			filter['value'] = splitted[0]
	}
  console.log(filter)

  params = {'regex': $('#regex').prop('checked') ? true : false }

  query = {'filter': filter, 'params': params}

  console.log(query)

  $.ajax({
    method: "POST",
    data: JSON.stringify(query),
    contentType: "application/json",
    url: $("#observables").data("url"),
    success: function(observables) {
      table = style_table($(observables))
      $("#observables").html(table);
    }
  })
}

function style_table(table) {
  return table
}
