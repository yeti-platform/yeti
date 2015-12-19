$(function() {
  scan_populate();

  setInterval(function() {
    scan_populate();
  }, 2000);
});

function scan_populate() {
  $(".yeti-populate").each(function() {
    yeti_populate($(this));
  });
}

function yeti_populate(elt) {

  var dest;

  url = elt.data('url');
  if (elt.data('dest') != undefined) {
    dest = $("#"+elt.data('dest'));
  } else {
    dest = elt;
  }

  $.ajax({
    method: "GET",
    contentType: "application/json",
    url: elt.data("url"),
    success: function(data) {
      dest.html(data);
    }
  });

}
