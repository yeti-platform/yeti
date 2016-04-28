function edit_context_listeners() {

  $("#context").on("click", "#add-context", function() {
    add_context();
  });

  $("#context").on("click", ".context-delete", function() {
    panel = $(this).closest('.yeti-panel');
    form = panel.find('form');
    delete_context(form);
  });

  $("#context").on("click", ".more-context", function() {
    // add input row
    table = $(this).closest(".context-panel").find('table').first();
    table.append($('<tr><th class="context-key"><input type="text" class="inline" value="key" name="keys"></th><td class="context-value"><input type="text" class="inline" name="values" value="value"></td></tr>'));
  });

  $("#context").on('click', '.context-edit', function() {

    panel = $(this).closest('.yeti-panel').first();
    panel.data('replace-context-source', panel.find('.panel-heading span').text())

    // make form editable
    form = panel.find('form').first();
    form.find("th,td").each(function () {
      $(this).html($('<input type="text" class="inline">').val($(this).text().trim()));
    });
    source = panel.find(".panel-title .content")
    source.html($('<input type="text" class="inline">').val(source.text()))

    // swap controls
    panel.find(".context-edit").toggle();
    panel.find(".context-save").toggle();
    panel.find(".context-delete").toggle();
    panel.find(".more-context").toggle();

  });

  $("#context").on('click', '.context-save', function() {
    panel = $(this).closest('.yeti-panel');
    form = panel.find('form');
    // send ajax request
    save_context(panel);

    // swap controls
    panel.find(".context-edit").toggle();
    panel.find(".context-save").toggle();
    panel.find(".context-delete").toggle();
    panel.find(".more-context").toggle();

  });

}

function add_context() {

  counter = "Context" + ($("#context .context-panel").size() + 1);

  markup = $(`<div class="panel panel-default yeti-panel context-panel">
                <div class="panel-heading">
                  <h4 class="panel-title"><span class="content">Analyst</span>
                  <button class="btn btn-default btn-xs pull-right more-context" style="display: none;"><span class="glyphicon glyphicon-plus" aria-hidden="true"></span> More</button>
                  <button class="btn btn-default btn-xs pull-right context-save" style="display: none;"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span> Save</button>
                  <button class="btn btn-danger btn-xs pull-right context-delete" style="display: none;"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span> Delete</button>
                  <button class="btn btn-default btn-xs pull-right context-edit"><span class="glyphicon glyphicon-pencil" aria-hidden="true"></span> Edit</button>
                  </h4>
                </div>
                <div class="panel-body panel-collapse" id="details-`+counter+`" role="tabpanel">
                  <form class="context-form">
                    <table class="table table-condensed">
                      <tr><th class="context-key">key</th><td class='context-value'>value</td></tr>
                    </table>
                  </form>
                </div>
            </div>`);

  $("#context").append(markup);
}

function get_context_dict(form) {
  dict = {};
  form.find('table tr').each(function() {
    key = $(this).find("th input").val();
    value = $(this).find("td input").val();
    dict[key] = value;
  });

  dict['source'] = form.closest('.context-panel').find('.panel-heading input').val()

  return dict;
}

function delete_context(form) {

  dict = get_context_dict(form);

  $.ajax({
    method: "DELETE",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: $("#context").data('endpoint'),
    data: JSON.stringify({"context": dict}),
    success: function(data) {
      form.closest(".context-panel").remove();
    },
    error: function(data) {
      notify("Error adding context.", "danger");
    }
  });

}

function save_context(panel) {

  form = panel.find('form');
  dict = get_context_dict(form);
  old_source = panel.data('replace-context-source');

  form.find('table tr').each(function() {
    key = $(this).find("th input").val();
    value = $(this).find("td input").val();
    dict[key] = value;
  });

  if (!('source' in dict)) {
    if (form.find('[name="source"]').val() == undefined) {
      dict['source'] = 'analyst';
    }
    else {
      dict['source'] = form.find('[name="source"]').val();
    }
  }

  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: $("#context").data('endpoint'),
    data: JSON.stringify({"context": dict, "old_source": old_source}),
    success: function(data) {
      table = form.find('table tbody');
      table.empty();
      for (var i in data) {
        if (i == "source") {
          panel.find(".panel-title .content").text(data[i]);
        }
        else {
          table.append('<tr><th class="context-key">'+i+'</th><td>'+data[i]+'</td></tr>');
        }
      }
    },
    error: function(data) {
      notify("Error adding context.", "danger");
    }
  });


}
