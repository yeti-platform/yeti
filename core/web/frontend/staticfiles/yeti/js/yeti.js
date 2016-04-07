$(function() {
  scan_populate();

  scan_clickable();

  scan_toggle();

  setInterval(function() {
    scan_populate(".auto-update");
  }, 2000);
});

function scan_toggle() {
  $("body").on('click', ".yeti-toggle", function(){
    tgt = $("#"+$(this).data('target'))
    tgt.toggle()
  });
}

function scan_populate(cls) {
  if (cls == undefined) {
    cls = "";
  }
  $(".yeti-populate" + cls).each(function() {
    yeti_populate($(this));
  });
}

function scan_clickable() {
  $(".yeti-content").on('click', '.yeti-clickable', function() {
    yeti_clickable($(this));
  });
}

function yeti_clickable(elt) {
  var url;
  var target;

  url = elt.data('url');
  if (elt.data('target') != undefined) {
    target = $("#"+elt.data('target'));
  } else {
    target = elt;
  }

  $.ajax({
    method: "GET",
    contentType: "application/json",
    url: url,
    success: function(data) {
      target.html(data);
    }
  });
}

function yeti_populate(elt) {

  var dest;
  var url;

  url = elt.data('url');
  if (elt.data('dest') != undefined) {
    dest = $("#"+elt.data('dest'));
  } else {
    dest = elt;
  }

  $.ajax({
    method: "GET",
    contentType: "application/json",
    url: url,
    success: function(data) {
      dest.html(data);
    }
  });

}

// Helper for notifications
function notify(message, type) {
  $.notify({
      message: message
    }, {
      offset: {
        y: 50,
        x: 30
      },
      type: type
  });
}
