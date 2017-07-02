class Action {
  constructor(template) {
    this.query = null;
    this.selected = new Set();
    this.template = Handlebars.compile($(template).html());
    this.callbacks = {};
    this.hiddenField = Handlebars.compile($('#action-hidden-field-template').html());
  }

  registerCallback(name) {
    this.callbacks[name] = [];
  }

  on(name, callback) {
    if (name in this.callbacks) {
      this.callbacks[name].push(callback);
    }
  }

  trigger(name, params) {
    params.selection = Array.from(this.selected);

    if (name in this.callbacks) {
      this.callbacks[name].forEach(function (callback) {
        callback(params);
      });
    }
  }

  shouldDisplay() {
    return true;
  }

  displayIn(location) {
    if (this.shouldDisplay()) {
      $(location).prepend(this.template(this));

      this.setupEvents(location);
    }
  }

  observableSelection() {
    var observables = [];

    this.selected.forEach(function (node) {
      if (node.startsWith("observable-")) {
        observables.push(node.substring(11));
      } else if (!node.startsWith("entity-")) {
        observables.push(node);
      }
    });

    return observables;
  }

  addToSelection(id) {
    this.selected.add(id);
  }

  removeFromSelection(id) {
    this.selected.delete(id);
  }

  selectOne(id) {
    this.selected.clear();
    this.addToSelection(id);
  }

  changeSelection(ids) {
    var self = this;

    self.reset();
    ids.forEach(self.addToSelection.bind(self));
  }

  reset() {
    this.selected.clear();
  }

  setupEvents(location) {
    var self = this;

    $(location).on('submit', '.selection-form', function (e) {
      self.enrichForm($(this));
    });
  }

  getQuery() {
    return JSON.stringify(build_params($('.yeti-crud')));
  }

  enrichForm(form) {
    var self = this;
    var idsDiv = form.find('.selection-ids');
    var selection = self.observableSelection();

    idsDiv.html('');
    if (selection.length === 0) {
      if ($('.yeti-crud').length > 0) {
        var query = self.getQuery();
        idsDiv.append(self.hiddenField({'name': 'query', 'value': query}));
      }
    }
    else {
      selection.forEach(function (id) {
        idsDiv.append(self.hiddenField({'name': 'ids', 'value': id}));
      });
    }
  }

}

class ManageTags extends Action {

  constructor(template) {
    super(template);
    this.choices = [];
    this.choices_url = $('#tags_url').data('url');

    this.registerCallback('tags.added');
    this.registerCallback('tags.removed');
  }

  shouldDisplay() {
    return (($('.yeti-crud').length > 0) || (this.observableSelection().length > 0));
  }

  displayIn(location) {
    super.displayIn(location);
    enable_tagfield($('#manage_tags'), this.choices, this.choices_url);
  }

  setupEvents(location) {
    var self = this;

    $(location).on('click', '#managetags-add', self.addTags.bind(self));
    $(location).on('click', '#managetags-remove', self.removeTags.bind(self));
  }

  updateTags(evt, url_id, evt_name) {
    var self = this;
    var url = $(url_id).data('url');
    var tags = $('#manage_tags').tokenfield('getTokensList');

    if (tags !== "") {
      tags = tags.split(',');

      var data = {
        'tags': tags,
      };
      var selection = self.observableSelection();

      if (selection.length > 0) {
        data.ids = selection;
      } else if ($('.yeti-crud').length > 0) {
        data.query = self.getQuery();
      }

      var spinner = $(evt.currentTarget).find('i');
      spinner.removeClass('hide');

      $.post(url, JSON.stringify(data)).done(function (data) {
          notify('Tags successfuly updated', 'success');
          spinner.addClass('hide');
          $('#manage_tags').tokenfield('setTokens', []);

          self.trigger(evt_name, {'tags': tags});
      });
    } else {
        notify('You have to select tags before', 'danger');
    }
  }

  addTags(evt) {
    this.updateTags(evt, '#tag_url', 'tags.added');
  }

  removeTags(evt) {
    this.updateTags(evt, '#untag_url', 'tags.removed');
  }

}

class Export extends Action {
  constructor(template) {
    super(template);
    this.fetched = false;
    this.templates = [];
    this.templatesUrl = $('#export_templates_url').data('url');
    this.exportUrl = $('#export_url').data('url');
    this.optionsTemplate = Handlebars.compile($('#action-export-options-template').html());
  }

  shouldDisplay() {
    return (($('.yeti-crud').length > 0) || (this.observableSelection().length > 0));
  }

  displayIn(location) {
    super.displayIn(location);
    $('#action-export-form').attr('action', this.exportUrl);
    this.setTemplates();
  }

  setTemplates() {
    var self = this;

    function fillOptions() {
      $('#selection-export-templates').html(self.optionsTemplate({'templates': self.templates}));
    }

    if (self.fetched) {
      fillOptions();
    } else {
      $.getJSON(self.templatesUrl, function (data) {
        self.fetched = true;
        if (data.length > 0) {
          data.forEach(function (template) {
            self.templates.push(template);
          });

          fillOptions();
        }
      });
    }
  }

  setupEvents(location) {
    super.setupEvents(location);

    $(location).on('submit', '.selection-form', function (e) {
      var select = $(e.currentTarget).find('select');

      if (!select.val()) {
        e.preventDefault();
        notify("You have to select a template first", "danger");
      }
    });
  }
}
