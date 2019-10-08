$(function() {
  $("#admin").on('click', '.admin-toggle', function() {
    toggle($(this));
  });
  $("#admin").on('click', '.admin-remove', function() {
    remove($(this));
  });
  $("#admin").on('click', '.admin-toadmin', function() {
    admins($(this));
  });
  $("#admin").on('click', '.admin-fromadmin', function() {
    admins($(this));
  });
});


function toggle(button) {
  console.log("TOGGLE")
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
