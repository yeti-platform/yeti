$(function(){

  $("form.yeti-crud").each(function(){

    refresh_table($(this));

    $(this).find(".crud-search").click(function() {
      form = $(this).closest("form").first();
      refresh_table(form);
    });

    $(this).find(".crud-filter").keydown(function (event) {
  		if (event.which == 13) {
  			event.preventDefault();
        form = $(this).closest("form").first();
  			refresh_table(form);
  		}
  	});

    $(this).find(".crud-paginator").click(function(event){
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

function add_to_filters(filters, key, value) {
  if (value instanceof Array) {
    return value.forEach(function (val) {
      add_to_filters(filters, key, val);
    });
  }

  if (value.toLowerCase() == "true")
    value = true;
  else if (value.toLowerCase() == "false")
    value = false;

  if (key in filters) {
    if (filters[key] instanceof Array)
      filters[key].push(value);
    else
      filters[key] = [filters[key], value];
  }
  else
    filters[key] = value;
}

function build_params(form) {
  var filter = form.find(".crud-filter").first();
  var queries = filter.val().split(' ');
  var default_field = filter.data('default-value');

  filter = {};

  for (var i in queries) {
    splitted = queries[i].split('=');
    if (splitted.length > 1)
      add_to_filters(filter, splitted[0], splitted[1].split(','));
    else if (splitted[0] !== "")
      add_to_filters(filter, default_field, splitted[0]);
  }

  // include extra filters from hidden inputs
  form.find(".extra-filter").each(function() {
    add_to_filters(filter, this.name, $(this).val());
  });

  params = {
    'regex': form.find('.crud-regex').prop('checked') ? true : false,
    'page': form.find(".crud-pagination").data('page'),
  };

  return {'filter': filter, 'params': params};
}

function refresh_table(form) {
  $("#spinner").toggle();
  $("#go").toggle();
  $("#go").parent().prop('disabled', true);

  query = build_params(form);

  $.ajax({
    method: "POST",
    data: JSON.stringify(query),
    contentType: "application/json",
    url: form.data("url"),
    success: function(data) {
      $("#"+form.data('target')).html(data);
    },
    complete: function(observables) {
      $("#spinner").toggle();
      $("#go").toggle();
      $("#go").parent().prop('disabled', false);
    }
  });
}
