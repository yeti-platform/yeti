$(function() {

  $(".yeti-form").each(function() {

    refresh_tagfields($(this));

    $(this).find("button.yeti-new").click(function(){
      yeti_new_button($(this));
    });

    // set save button
    $(this).find("button.yeti-save").click(function(){
      yeti_save_button($(this));
    });

    // set delete button
    $(this).find("button.yeti-delete").click(function(){
      yeti_delete_button($(this));
    });

    // set clear button
    $(this).find("button.yeti-clear").click(function(){
      yeti_clear_button($(this));
    });

    if ($(this).data('start-disabled')) {
      disable_form($(this));
    }

  });

  // set edit behavior
  $(this).find(".yeti-content").on('click', '.yeti-edit-elt', function() {
    yeti_edit_elt($(this));
  });

});

function yeti_clear_button(elt) {
  console.log(elt.closest("form").first())
  clear_form(elt.closest("form").first())
}

function enable_controls(form, controls) {
  for (var i in controls) {
    form.find(".yeti-"+controls[i]).removeClass('hidden');
  }
}

function disable_controls(form, controls) {
  for (var i in controls) {
    form.find(".yeti-"+controls[i]).addClass('hidden');
  }
}

function disable_form(form) {
  console.log(form);
  form.find(".form-group > input").prop('disabled', true);
  form.find("textarea").prop('disabled', true);
  form.find("select").prop('disabled', true);
  form.find(".tagfield").tokenfield('disable');

  disable_controls(form, ['save', 'delete', 'clear']);
  enable_controls(form, ['new']);
}

function enable_form(form) {
  console.log(form.find("input"));
  form.find("input").prop('disabled', false);
  form.find("textarea").prop('disabled', false);
  form.find("select").prop('disabled', false);
  form.find(".tagfield").tokenfield('enable');

  disable_controls(form, ['new']);
  enable_controls(form, ['save', 'delete', 'clear']);
}



function clear_form(form) {

  // clear input fields
  form.find("input:not(.tagfield)").val("");
  form.find("textarea").val("");
  form.find("input.tagfield").each(function(){
    $(this).val("");
    $(this).tokenfield("setTokens", []);
  });

  // reset button to their original state
  form.find("button.yeti-save").text('New');
  console.log(form.data("url"))
  form.find("button.yeti-save").data('url', form.data('url'));
  console.log(form.find("button.yeti-save").data('url'));


  // disable delete button
  form.find("button.yeti-delete").first().attr('disabled', 'disabled');

  disable_form(form)

}

function yeti_new_button(elt) {
  var url = elt.data('url');
  var form = elt.closest("form").first();

  enable_form(form);
  disable_controls(form, ['delete']);
}

function yeti_delete_button(elt) {
  var url = elt.data('url');
  var form = elt.closest("form").first();

  $.ajax({
    method: "DELETE",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    success: function(data) {
      scan_populate();
      clear_form(form);
      refresh_tagfields(form);
      // $("#yeti-save-tag").addAttr("disabled");
      // $("#yeti-delete-tag").addAttr("disabled");
    }});
}

function yeti_save_button(elt) {
  var url = elt.data('url');
  var clear = elt.data('clear');
  var form = elt.closest("form").first();

  // operation on forms
  data = form.serializeYetiObject();
  $.ajax({
    method: "POST",
    data: JSON.stringify(data),
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    success: function(data) {
      scan_populate();
      if (clear) {
        clear_form(form);
      }
      refresh_tagfields(form);
      notify("Changes saved successfully", "success")
    }}).fail(function(data) {
      notify("Could not save changes", "danger");
    });
}

function yeti_edit_elt(elt) {
  // get elt info
  var url = elt.data('url');
  var form = $("#"+elt.data('form'));
  enable_form(form);

  $.ajax({
    method: "GET",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    success: function(data) {
      populate_form(data, form)
      form.find("button.yeti-save").data("url", url);
      form.find("button.yeti-save").text("Save");
      form.find("button.yeti-delete").data("url", url);
      form.find("button.yeti-delete").removeAttr('disabled');
    }
  });

  $(".yeti-edit-elt").removeClass("selected");
  elt.toggleClass("selected");
}

function populate_form(data, form) {
  for (i in data) {
    form.find("[name="+i+"]:not(.tagfield)").val(data[i]);
    form.find("[name="+i+"].tagfield").each(function(){
      $(this).val("");
      $(this).tokenfield("setTokens", data[i]);
    });
  }
}
