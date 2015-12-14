$(function() {
  $(".yeti-tag").click(function() {
    add_tag($(this));
  });

  $(".tag-all").click(function() {
    tag_all($(this));
  })
});

function add_tag(elt) {
  tag = elt.data('tag');
  id = elt.parent().parent().data('id');
  // do ajax request
}

function tag_all(elt) {
  id = elt.parent().parent().data('id');
  tags = [];
  elt.parent().parent().find(".yeti-tag").each(function() {
    tags.push($(this).data('tag'));
  });
  // do ajax request
}
