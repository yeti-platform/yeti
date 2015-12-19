$(function() {
  $.ajax({
    method: "GET",
    contentType: "application/json",
    url: $("#feed-table").data("url"),
    success: function(feeds) {
      $("#feed-table").html(feeds);
    }
  });
});
