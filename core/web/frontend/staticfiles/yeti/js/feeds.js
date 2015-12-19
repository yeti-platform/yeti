$(function() {

  reload_feeds();

  $("#feed-table").on('click', '.feed-toggle', function() {
    toggle_feed($(this));
  });

  $("#feed-table").on('click', '.feed-refresh', function() {
    refresh_feed($(this));
  });

  setInterval(function() {
    reload_feeds();
  }, 2000);

});

function reload_feeds() {
  $.ajax({
    method: "GET",
    contentType: "application/json",
    url: $("#feed-table").data("url"),
    success: function(feeds) {
      $("#feed-table").html(feeds);
    }
  });
}


function toggle_feed(button) {
  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    url: button.data("url"),
    success: function(data) {
      button.toggleClass("glyphicon glyphicon-ok");
      button.toggleClass("glyphicon glyphicon-remove");
    }
  });
}

function refresh_feed(button) {
  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    url: button.data("url"),
    success: function(data) {
      console
      button.parent().parent().find(".status").text("Refreshing...");
    }
  });
}
