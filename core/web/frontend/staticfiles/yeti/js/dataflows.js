$(function() {

  $("#feed-table").on('click', '.feed-toggle', function() {
    toggle($(this));
  });

  $("#export-table").on('click', '.export-toggle', function() {
    toggle($(this));
  });

  $("#feed-table").on('click', '.feed-refresh', function() {
    refresh($(this));
  });

  $("#export-table").on('click', '.export-refresh', function() {
    refresh($(this));
  });

});


function toggle(button) {
  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    url: button.data("url"),
    success: function(data) {
      button.toggleClass("glyphicon glyphicon-ok");
      button.toggleClass("glyphicon glyphicon-remove");
      button.parent().parent().toggleClass("disabled")
    }
  });
}

function refresh(button) {
  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    url: button.data("url")
  });
}
