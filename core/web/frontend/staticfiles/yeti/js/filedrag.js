$(function () {

  $("#dropzone").on('dragenter', function(e) {
    $(this).addClass("dragging");
  });

  $("#dropzone").on('dragleave', function(e) {
    $(this).removeClass("dragging");
  });

  $("#dropzone input").on('change', function(e) {
    var files = $(this)[0].files;
    var span = $("#dropzone span");
    if (files.length > 1) {
      span.html("<strong>" + files.length + "</strong> files selected");
    }
    else if (files.length == 1) {
      span.html("<strong>1</strong> file selected");
    }
  });

});
