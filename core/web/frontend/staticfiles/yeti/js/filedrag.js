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
      span.html("Selected <strong>" + files[0].name + "</strong>");
    }
  });


  $("form.dropzone").on('submit', function(e) {
    e.preventDefault();
    e.stopPropagation();

    form = $(this)
    form.find(".btn.upload").prop('disabled', true)
    form.find('span').html("<strong>Uploading...</strong>")
    ajaxFormData = new FormData();

    files = form.find("input[type=file]")[0].files

    for (var i = 0; i < files.length; i++) {
      ajaxFormData.append("files", files[i], files[i].name);
    }

    ajaxFormData.append("unzip", form.find(".checkbox.zip input").prop('checked'))

    $.ajax({
      method: "POST",
      headers: {"Accept": "application/json"},
      processData: false,
      contentType: false,
      url: $(this).attr('action'),
      data: ajaxFormData,
      success: function(data) {
        $("#file-upload-modal").modal('toggle');
        notify("Succesfully uploaded " + data.length + " files.", "success");
        form.find('span').html("<strong>Drag &amp; drop</strong> or <strong>click</strong> to add files")
        form.find("input").val('');
        form.find(".btn.upload").prop('disabled', false)
      }
    });

  })

})
