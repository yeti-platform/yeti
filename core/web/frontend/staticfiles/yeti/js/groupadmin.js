$(function() {

  $("#groups").on('click', '.group-toggle', function() {
    toggle($(this));
  });

  $("#groups").on('click', '.group-remove', function() {
    remove($(this));
  });
  $("#groups").on('click', '.group-toadmin', function() {
    admins($(this));
  });
  $("#groups").on('click', '.group-fromadmin', function() {
    admins($(this));
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

function remove(button) {
  if (confirm("Are you sure?")) {
    $.ajax({
      method: "POST",
      headers: {"Accept": "application/json"},
      url: button.data("url"),
      success: function(data) {
        $(".crud-search").click()
      }
    });
  }
}

function admins(button) {
  if (confirm("Are you sure?")) {
    $.ajax({
      method: "POST",
      headers: {"Accept": "application/json"},
      url: button.data("url"),
      success: function(data) {
        $(".crud-search").click()
      }
    });
  }
}
