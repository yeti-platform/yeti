$(function() {
  $(".yeti-tag").click(function() {
    add_tag($(this));
  });

  $(".tag-all").click(function() {
    tag_all($(this));
  });

  $(".add-observable").click(function() {
    add_observable($(this));
  });

});

function add_tag(elt) {
  tag = elt.data('tag');
  url = elt.closest('tr').data('url');

  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    data: JSON.stringify({"tags": tag}),
    success: function(data) {
      console.log(data);
      elt.addClass("tag-added");
    }
  });

}

function tag_all(elt) {
  id = elt.parent().parent().data('id');
  tags = [];
  elt.parent().parent().find(".yeti-tag").each(function() {
    tags.push($(this).data('tag'));
  });
  // do ajax request
}

function add_observable(elt) {
  value = elt.data('value')
  url = elt.data('url')

  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    data: JSON.stringify({"value": value}),
    success: function(data) {
      a = $("<a>");
      a.attr("href", data['human_url']);
      a.text(data['id']);
      tr = elt.closest('tr');
      tr.find(".yeti-disabled").removeClass('yeti-disabled');
      tr.data('url', data['url']);
      elt.replaceWith(a);
    }
  });

}


function tag_element(tag, element_id) {
  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: elt.data('choices'),
    success: function(data) {
      console.log("OK");
    }
  }); // end ajax call
}
