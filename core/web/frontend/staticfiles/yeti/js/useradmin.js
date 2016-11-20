$(function() {

  $("#users").on('click', '.user-toggle', function() {
    toggle($(this));
  });

  $("#users").on('click', '.user-remove', function() {
    remove($(this));
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
