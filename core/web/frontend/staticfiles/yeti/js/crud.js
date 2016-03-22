$(function(){

  $("form.yeti-crud").each(function(){

    refresh_table($(this));

    $(this).find(".crud-search").click(function() {
      form = $(this).closest("form").first();
      refresh_table(form)
    });

    $(".crud-filter").keydown(function (event) {
  		if (event.which == 13) {
  			event.preventDefault();
        form = $(this).closest("form").first();
  			refresh_table(form);
  		}
  	});

    $(".crud-paginator").click(function(event){
      event.preventDefault();
      direction = $(this).data('direction')
      form = $(this).closest("form").first();
      change_page(form, direction);
      refresh_table(form);
    });

  });

});

function change_page(form, direction) {
  page = form.find(".crud-pagination").data('page');
  newpage = page+direction;
  if (newpage < 1) {
    newpage = 1;
  }
  form.find(".crud-pagination").data('page', newpage);
  form.find(".crud-pagenumber").text(newpage);
}

function refresh_table(form) {
  $("#spinner").toggle();
  $("#go").toggle();
  $("#go").parent().prop('disabled', true);

  filter = form.find(".crud-filter").first()
  queries = filter.val().split(' ');
  default_field = filter.data('default-value');
	filter = {};

  for (var i in queries) {
		splitted = queries[i].split('=');
		if (splitted.length > 1)
			filter[splitted[0]] = splitted[1].split(',');
		else if (splitted[0] != "")
			filter[default_field] = splitted[0];
	}

  // include extra filters from hidden inputs
  form.find(".extra-filter").each(function() {
    filter[this.name] = $(this).val()
  });

  params = {'regex': form.find('.crud-regex').prop('checked') ? true : false,
            'page': form.find(".crud-pagination").data('page'),
            }

  query = {'filter': filter, 'params': params}

  $.ajax({
    method: "POST",
    data: JSON.stringify(query),
    contentType: "application/json",
    url: form.data("url"),
    success: function(observables) {
      table = style_table($(observables))
      $("#"+form.data('target')).html(table);
    },
    complete: function(observables) {
      $("#spinner").toggle();
      $("#go").toggle();
      $("#go").parent().prop('disabled', false);
    }
  });
}

function style_table(table) {
  return table
}
