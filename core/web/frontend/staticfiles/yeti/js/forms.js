
function refresh_tagfields(form) {



  // set tagfields
  tagfield = form.find(".tagfield").each(function(index){

    var global_tags = []

    var elt = $(this);
    $.ajax({
      method: "GET",
      headers: {"Accept": "application/json"},
      contentType: "application/json",
      url: elt.data('choices'),
      success: function(data) {
        for (i in data) {
          global_tags.push(data[i].name);
        }
        elt
        .on('tokenfield:createtoken', function (e) {
          if ($(this).data('choices')) {
            re = /^[a-zA-Z0-9_]+$/;
            charset = re.test(e.attrs.value);
            unique = $(this).val().split(',').indexOf(e.attrs.value) == -1;
            return charset && unique;
          }
        })
        .tokenfield({
          autocomplete: {
            source: global_tags,
            delay: 100
          },
          showAutocompleteOnFocus: true,
          delimiter: [',', ';', ' '],
          beautify: false
        });
      }
    });
  });
}

$(function() {

  $(".yeti-form").each(function() {

    refresh_tagfields($(this))

    // // set save button
    $(this).find("button.yeti-save").click(function(){
      yeti_save_button($(this));
    });

    // // set delete button
    $(this).find("button.yeti-delete").click(function(){
      yeti_delete_button($(this));
    });

    // set clear button
    $(this).find("button.yeti-clear").click(function(){
      yeti_clear_button($(this));
    });

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

function clear_form(form) {

  // clear input fields
  form.find("input:not(.tagfield)").val("");
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
      clear_form(form);
      refresh_tagfields(form);
    }});
}

function yeti_edit_elt(elt) {
  // get elt info
  var url = elt.data('url');
  var form = $("#"+elt.data('form'));

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

// serialization function
$.fn.serializeYetiObject = function()
{
    var o = {};
    var a = this.serializeArray();
    $.each(a, function() {
        if (o[this.name] !== undefined) {
            if (!o[this.name].push) {
                o[this.name] = [o[this.name]];
            }
            o[this.name].push(this.value || '');
        } else {
            o[this.name] = this.value || '';
        }
    });
    return o;
};
