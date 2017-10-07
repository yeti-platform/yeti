function enable_tagfield(field, tags, url) {
  function enable_field(choices) {
    field.tokenfield({
      autocomplete: {
        source: choices,
        delay: 100
      },
      showAutocompleteOnFocus: true,
      delimiter: [',', ';'],
      beautify: false,
      createTokensOnBlur: true,
    });

    field.on('tokenfield:createtoken', function (e) {
      re = /^[a-zA-Z0-9_ ()-]+$/;
      charset = re.test(e.attrs.value);
      unique = !$(this).tokenfield('getTokensList').split(',').includes(e.attrs.value);
      return charset && unique;
    });
  }

  if (tags.length) {
    enable_field(tags);
  } else {
    $.getJSON(url, function (data) {
        for (var t in data) {
          tags.push(data[t].name);
        }

        enable_field(tags);
    });
  }
}

function refresh_tagfields(form) {
  var choices = [];

  form.find(".tagfield").each(function(index) {
    var field = $(this);
    enable_tagfield(field, choices, field.data('choices'));
  });
}
