$(function() {

  $("#tags-merge-selected").click(function(){
    tags_merge_selected($(this));
  });

});

function tags_merge_selected(button) {

  var url = button.data('url');
  var tags = []
  $("input:checked").each(function(){
    tags.push($(this).val())
  });

  merge_into = $("#merge-into").val()
  merge = $("#merge-tag").val().split(',')

  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    data: JSON.stringify({"merge_into": merge_into, "merge": merge}),
    success: function(data) {
      scan_populate();
    }
  });

}
