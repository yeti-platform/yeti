$(function(){

  refresh_table("");

  $("#observable-search").click(refresh_table);

  $("#observable-filter").keydown(function (event) {
		if (event.which == 13) {
			event.preventDefault();
			refresh_table();
		}
	});

  $(".paginator").click(function(event){
    event.preventDefault();
    change_page($(this).data('direction'));
    refresh_table();
  });

});

function change_page(direction) {
  page = $("#pagination").data('page');
  newpage = page+direction;
  if (newpage < 1) {
    newpage = 1;
  }
  $("#pagination").data('page', newpage);
  $("#pagenumber").text(newpage);
}

function refresh_table() {

  queries = $('#observable-filter').val().split(' ');
	filter = {};

  for (var i in queries) {
		splitted = queries[i].split('=');
		if (splitted.length > 1)
			filter[splitted[0]] = splitted[1];
		else if (splitted[0] != "")
			filter['value'] = splitted[0];
	}

  console.log(filter)

  params = {'regex': $('#regex').prop('checked') ? true : false,
            'page': $("#pagination").data('page'),
            }


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
  });
}

function style_table(table) {
  return table
}
