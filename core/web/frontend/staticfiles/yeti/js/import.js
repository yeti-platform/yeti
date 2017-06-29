class Import {
  constructor() {
    var self = this;

    self.nodes = new vis.DataSet([]);
    self.next_id = 1;

    self.initEvents();
  }

  setTemplates() {
    var self = this;

    self.nodeTypeTemplate = Handlebars.compile($('#import-type-template').html());
    self.nodeTemplate = Handlebars.compile($('#import-node-template').html());
    self.nodeEditTemplate = Handlebars.compile($('#import-node-edit').html());
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
      $('#import-nodes-lists').append(self.nodeTypeTemplate({type: node.type}));
    }

    // Append item to the list
    $('#import-nodes-' + node.type).append(self.nodeTemplate(node));

    // Enable tokenfield
    self.initTokenField(node.id);
  }

  // Highlight a term in the PDF reader
  hightlightInPdf(term) {
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

  // Highlight a term in the text viewer
  highlightInText(term) {
    var content = $('#textviewer');
    var results;

    function jumpTo() {
      if (results.length) {
        var position;
        var current = results.eq(0);

        if (current.length) {
          content.scrollTop(current[0].offsetTop - 20);
        }
      }
    }

    content.unmark({
      done: function() {
        content.mark(term, {
          done: function() {
            results = content.find("mark");
            jumpTo();
          }
        });
      }
    });
  }

  highlight(term, event) {
    var self = this;

    if ($('.pdfviewer').length > 0) {
      return this.hightlightInPdf(term);
    } else {
      this.highlightInText(term);
      return event;
    }
  }

  nodeClicked(event) {
    var self = this;

    var match = $(event.currentTarget).find('.match').text();
    var hlEvent = self.highlight(match, event);

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

    node.replaceWith(self.nodeEditTemplate(nodeObject));
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
    node.replaceWith(self.nodeTemplate(self.nodes.get(nodeId)));
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

  submitNodes(event) {
    var self = this;

    event.preventDefault();

    var button = $(event.currentTarget);
    var spinner = button.find('i');
    var url = button.data('url');
    var nodes = self.nodes.get({
      filter: function (node) {
        return node.to_import;
      },
      fields: ['value', 'type', 'new_tags'],
    });

    function callback(data) {
      if (data.status === 'error') {
        notify(data.message, "danger");
      } else {
        window.location = $('#import_view').data('investigation-url');
      }

      spinner.addClass('hide');
    }

    spinner.removeClass('hide');
    spinner.addClass('spinner');

    $.ajax({
      type: 'POST',
      url: url,
      data: JSON.stringify({nodes: nodes}),
      success: callback,
      dataType: 'json',
      contentType: 'application/json',
    });
  }

  // Bind functions to events
  initEvents() {
    var self = this;

    $('#import-nodes-lists').on('click', 'li.import-node', self.nodeClicked.bind(self));
    $('#import-nodes-lists').on('click', '.import-node-remove', self.nodeRemoved.bind(self));
    $('#import-nodes-lists').on('click', '.import-node-edit', self.nodeEdit.bind(self));
    $('#import-nodes-lists').on('submit', '.import-node-form', self.nodeEdited.bind(self));
    $('#import-nodes-lists').on('focusout', '.import-node-form input', self.nodeEdited.bind(self));
    $('#import_send').click(self.submitNodes.bind(self));
  }
}

function fetchImportResults(url) {
  function callback(data) {
    if (data.status == 'finished') {
      window.location = $('#investigation-import').data('next');
    } else if (data.status == 'error') {
      $('#investigation-import').text('Error during import: ' + data.error);
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

function toggleImportSource(event) {
  event.preventDefault();

  $('#investigation_description').toggleClass('hide');
  $('#investigation_source').toggleClass('hide');

  $('#show_description').toggleClass('hide');
  $('#show_import').toggleClass('hide');
}

$(function () {
  var import_results = $('#investigation-import');
  if (import_results.length) {
    var url = import_results.data('url');

    fetchImportResults(url);
  }

  $('#show_import').click(toggleImportSource);
  $('#show_description').click(toggleImportSource);
});
