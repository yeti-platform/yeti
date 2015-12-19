$(function() {

  $("#scheduled-table").on('click', '.analytics-refresh', function() {
    refresh_analytics($(this));
  });

  $("#scheduled-table").on('click', '.analytics-toggle', function() {
    toggle_analytics($(this));
  });

  $("#oneshot-table").on('click', '.analytics-toggle', function() {
    toggle_analytics($(this));
  });

});

function refresh_analytics(button) {
  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    url: button.data("url")
  });
}

function toggle_analytics(button) {
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
