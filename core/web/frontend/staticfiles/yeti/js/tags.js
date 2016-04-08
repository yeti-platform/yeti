$(function() {

  $("#tags-merge-selected").click(function(){
    tags_merge_selected($(this));
  });

});

function tags_merge_selected(button) {

  var url = button.data('url');
  var tags = [];
  $("input:checked").each(function(){
    tags.push($(this).val());
  });

  merge_into = $("#merge-into").val();
  merge = $("#merge-tag").val().split(',');
  make_dict = $("[name='make-dict']:checked").length == 1 ? true : false;

  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    data: JSON.stringify({"merge_into": merge_into, "merge": merge, "make_dict": make_dict}),
    success: function(data) {
      scan_populate();
    }
  }).fail(function (data) {
    notify("Could not merge selected tags.", "danger");
  });

}
