$(function() {

  $("#feed-table").on('click', '.feed-toggle', function() {
    toggle_feed($(this));
  });

  $("#feed-table").on('click', '.feed-refresh', function() {
    refresh_feed($(this));
  });

  setInterval(function() {
    scan_populate();
  }, 2000);

});


function toggle_feed(button) {
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

function refresh_feed(button) {
  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    url: button.data("url"),
    success: function(data) { }
  });
}
