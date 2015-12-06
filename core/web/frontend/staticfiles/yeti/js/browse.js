$(function(){
  refresh_table();
});


function refresh_table() {
  $.ajax({
    // dataType: "json",
    url: $("#observables").data("url"),
    success: function(observables) {
      table = style_table($(observables))
      $("#observables").html(table);
    }
  })
}

function style_table(table) {
  table.toggleClass("table table-condensed table-yeti table-hover")
  table.find('.yeti-tag').toggleClass('label label-default')
  table.find('.yeti-tag.fresh').toggleClass('label-primary')
  return table
}
