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

$(function () {
  var import_results = $('#investigation-import');
  if (import_results.length) {
    var url = import_results.data('url');

    fetchImportResults(url);
  }
});
