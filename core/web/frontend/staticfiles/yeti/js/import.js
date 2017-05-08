var nodeTypeTemplate = Handlebars.compile($('#import-type-template').html());
var nodeTemplate = Handlebars.compile($('#import-node-template').html());
var nodeEditTemplate = Handlebars.compile($('#import-node-edit').html());


class Import {
  constructor() {
    var self = this;

    self.nodes = new vis.DataSet([]);
    self.next_id = 1;

    self.initEvents();
  }

  addNodes(nodes) {
    var self = this;

    Object.keys(nodes).forEach(function (match) {
      var nodeObject = this[match];

      nodeObject.id = self.next_id;
      nodeObject.match = match;
      nodeObject.new_tags = '';
      nodeObject.to_import = true;
      self.nodes.add(nodeObject);
      self.displayNode(nodeObject);

      self.next_id = self.next_id + 1;
    }, nodes);
  }

  displayNode(node) {
    var self = this;

    // First, see if this type of node is already listed
    if ($('#import-nodes-' + node.type).length === 0) {
      // If not, create list before filling it
      $('#import-nodes-lists').append(nodeTypeTemplate({type: node.type}));
    }

    // Append item to the list
    $('#import-nodes-' + node.type).append(nodeTemplate(node));

    // Enable tokenfield
    self.initTokenField(node.id);
  }

  // Highlight a term in the PDF reader
  highlight(term) {
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

    win.PDFViewerApplication.findBar.dispatchEvent(event);

    return event;
  }

  nodeClicked(event) {
    var self = this;

    var match = $(event.currentTarget).find('.match').text();
    var hlEvent = self.highlight(match);

    // Give focus to the tag input
    var target = $(event.currentTarget);
    if (!target.is('input')) {
      target = target.find('input.tokenfield');
    }
    target.data('bs.tokenfield').focusInput(hlEvent);
  }

  nodeRemoved(event) {
    var self = this;

    event.preventDefault();
    event.stopPropagation();

    var node = $(event.currentTarget).closest('.import-node');
    var nodeId = node.data('id');
    var nodeObject = self.nodes.get(nodeId);

    node.remove();
    self.nodes.update({id: nodeId, to_import: false});

    var list = $('#import-nodes-' + nodeObject.type);
    if (list.children().length === 0) {
      list.closest('.import-type').remove();
    }
  }

  nodeEdit(event) {
    var self = this;

    event.preventDefault();
    event.stopPropagation();

    var node = $(event.currentTarget).closest('.import-node');
    var nodeId = node.data('id');
    var nodeObject = self.nodes.get(nodeId);

    node.replaceWith(nodeEditTemplate(nodeObject));
    $('#import-node-edit-' + nodeId).focus();
    // This is a hack so that cursor is placed at the end of text
    $('#import-node-edit-' + nodeId).val(nodeObject.value);
  }

  nodeEdited(event) {
    var self = this;

    event.preventDefault();

    var form = $(event.currentTarget);
    var node = form.closest('li');
    var nodeId = node.data('id');

    var newValue = '';
    if (form.is('input')) {
      newValue = form.val();
    } else {
      newValue = form.find('input').val();
    }

    self.nodes.update({id: nodeId, value: newValue});
    node.replaceWith(nodeTemplate(self.nodes.get(nodeId)));
    self.initTokenField(nodeId);
  }

  saveTags(event) {
    var self = this;

    var field = $(event.currentTarget);
    var nodeId = field.closest('li').data('id');
    var tokenfield = field.data('bs.tokenfield');

    self.nodes.update({id: nodeId, new_tags: tokenfield.getTokensList()});
  }

  initTokenField(nodeId) {
    var self = this;

    var node = self.nodes.get(nodeId);

    // Initialize tokenfield and event listener
    $('#import-node-' + nodeId + ' input')
    .on('tokenfield:createdtoken', self.saveTags.bind(self))
    .on('tokenfield:removedtoken', self.saveTags.bind(self))
    .tokenfield({createTokensOnBlur: true});

    // Add saved tags
    $('#import-node-' + nodeId + ' input').tokenfield('setTokens', node.new_tags);
  }

  // Bind functions to events
  initEvents() {
    var self = this;

    $('#import-nodes-lists').on('click', 'li.import-node', self.nodeClicked.bind(self));
    $('#import-nodes-lists').on('click', '.import-node-remove', self.nodeRemoved.bind(self));
    $('#import-nodes-lists').on('click', '.import-node-edit', self.nodeEdit.bind(self));
    $('#import-nodes-lists').on('submit', '.import-node-form', self.nodeEdited.bind(self));
    $('#import-nodes-lists').on('focusout', '.import-node-form input', self.nodeEdited.bind(self));
  }
}


// function fetchImportResults(url) {
//   function callback(data) {
//     if (data.status == 'finished') {
//       window.location = $('#investigation-import').data('next');
//     } else if (data.status == 'error') {
//       $('#investigation-import').text('Error during import:' + data.error);
//     } else {
//       setTimeout(fetchImportResults.bind(undefined, url), 1000);
//     }
//   }
//
//   $.get(
//     url,
//     {},
//     callback,
//     'json'
//   );
// }
//
//
// $(function () {
//     $('#import_observables li').click(function (e) {
//         var observable_div = $(this);
//         match = observable_div.find('.match').text();
//         highlight(match);
//     });
//
//     $('#import_send').click(function (e) {
//       e.preventDefault();
//       var nodes = [];
//       var url = $(this).data('url');
//
//       $('.import-node-value').each(function(i) {
//         var node = $(this);
//         nodes.push({
//             'type': node.data('type'),
//             'value': node.text(),
//         });
//       });
//
//       function callback(data) {
//         window.location = $('#import_view').data('investigation-url');
//       }
//
//       $.ajax({
//         type: 'POST',
//         url: url,
//         data: JSON.stringify({nodes: nodes}),
//         success: callback,
//         dataType: 'json',
//         contentType: 'application/json',
//       });
//     });
//
//     $('#import_observables').on('click', '.import-node-remove', function (e) {
//       e.preventDefault();
//
//       line = $(this).closest('.import-node');
//       value = line.find('.import-node-value');
//       value.removeClass('import-node-value');
//       line.addClass('hide');
//     });
//
//     var import_results = $('#investigation-import');
//     if (import_results.length) {
//       var url = import_results.data('url');
//
//       fetchImportResults(url);
//     }
// });
