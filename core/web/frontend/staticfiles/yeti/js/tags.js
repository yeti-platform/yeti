$(function() {

  var tags = [];
  var url = $("#tags-table").data("url")

  $.ajax({
    method: "GET",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    success: function(data) {
      for (i in data) {
        tags.push(data[i].name);
        console.log(data[i].name);
      }
      $('#tagfield').tokenfield({
        autocomplete: {
          source: tags,
          delay: 100
        },
        showAutocompleteOnFocus: true
      });
    }
  });

  $(".yeti-content").on('click', '.yeti-edit-tag', function() {
    yeti_edit_tag($(this));
  });

  $("#yeti-save-tag").click(function(){
    yeti_save_tag($(this));
  });

  $("#yeti-delete-tag").click(function(){
    yeti_delete_tag($(this));
  });

});

function yeti_delete_tag(elt) {
  url = elt.data('url');

  $.ajax({
    method: "DELETE",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    success: function(data) {
      scan_populate();
      $("#yeti-save-tag").addAttr("disabled");
      $("#yeti-delete-tag").addAttr("disabled");
    }});
}

function yeti_save_tag(elt) {
  url = elt.data('url');

  implied = $('#tagfield').tokenfield("getTokensList", ",", false).split(',');
  name = $("#selected-tag").val()

  $.ajax({
    method: "POST",
    data: JSON.stringify({"implied": implied, "name": name}),
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    success: function(data) {
      scan_populate();
    }});
}

function yeti_edit_tag(elt) {
  $("#yeti-save-tag").removeAttr("disabled");
  $("#yeti-delete-tag").removeAttr("disabled");
  var implied_tags = []

  implies = elt.find(".implied span.yeti-tag").each(function(index) {
    implied_tags.push($(this).data('tag'))
  });

  // set form
  $("#selected-tag-name").text(elt.find("span").data('tag'));
  $("#selected-tag").val(elt.find("span").data('tag'));
  $('#tagfield').tokenfield("setTokens", implied_tags);
  $("#yeti-save-tag").data('url', elt.data('url'));
  $("#yeti-delete-tag").data('url', elt.data('url'));

  // colorize
  $(".yeti-edit-tag").removeClass("selected");
  elt.toggleClass("selected");
}
