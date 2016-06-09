$(function() {
  scan_populate();

  scan_clickable();

  scan_toggle();

  permanent_tabs();

  setInterval(function() {
    scan_populate(".auto-update");
  }, 2000);
});


function permanent_tabs() {
  h = window.location.hash

  if (h != undefined ) {
    $('a[href="'+h+'"]').tab('show');
  }

  $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        window.location.hash = $(this).attr('href');
  });

}

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
          if (this.name == "tags") {
            o[this.name] = this.value.split(',') || [];
          }
          else {
            o[this.name] = this.value || '';
          }
        }
    });
    return o;
};

$.fn.serializeObject = function()
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
