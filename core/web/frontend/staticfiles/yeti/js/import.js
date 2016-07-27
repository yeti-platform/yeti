function fetchImportResults(url) {
  function callback(data) {
    if (data.status == 'finished') {
      window.location = $('#investigation-import').data('next');
    } else if (data.status == 'error') {
      $('#investigation-import').text('Error during import:' + data.error);
    } else {
      setTimeout(fetchImportResults.bind(undefined, url), 1000);
    }
  }

  $.get(
    url,
    {},
    callback,
    'json'
  );
}

function highlight(term) {
    var win = document.getElementById('pdfviewer').contentWindow;

    win.PDFViewerApplication.findBar.open();
    $(win.PDFViewerApplication.findBar.findField).val(term);

    var event = document.createEvent('CustomEvent');
    event.initCustomEvent('findagain', true, true, {
        query: term,
        caseSensitive: $("#findMatchCase").prop('checked'),
        highlightAll: $("#findHighlightAll").prop('checked', true),
        findPrevious: undefined
    });

    win.PDFViewerApplication.findBar.dispatchEvent('');

    return event;
}

$(function () {
    $('#import_observables li').click(function (e) {
        var observable_div = $(this);
        match = observable_div.find('.match').text();
        highlight(match);
    });

    $('#import_send').click(function (e) {
      e.preventDefault();
      var nodes = [];

      $('.import-node-value').each(function(i) {
        var node = $(this);
        nodes.push({
            'type': node.data('type'),
            'value': node.text(),
        });
      });

      console.log(nodes);
    });

    var import_results = $('#investigation-import');
    if (import_results.length) {
      var url = import_results.data('url');

      fetchImportResults(url);
    }
});
