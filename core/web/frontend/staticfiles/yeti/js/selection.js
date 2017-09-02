class SelectionManager {

  constructor(table_selector, row_selector) {
    this.selected = new Set();
    this.enableSelection(table_selector, row_selector);

    this.manageTags = new ManageTags('#action-managetags-template');
    this.manageTags.displayIn('#accordion');
    this.manageTags.on('tags.added', this.refresh.bind(this));
    this.manageTags.on('tags.removed', this.refresh.bind(this));

    this.export = new Export('#action-export-template');
    this.export.displayIn('#accordion');
  }

  reset() {
    this.selected = new Set();
    this.manageTags.reset()
    this.export.reset()
    this.updateSelectedCount();
  }

  refresh() {
    refresh_table($('.yeti-crud'));
    this.reset();
  }

  updateSelectedCount() {
    $('#selection-count').text(this.selected.size);

    if (this.selected.size === 0) {
      $('#selection-specific').addClass('hidden');
      $('#selection-all').removeClass('hidden');
    } else {
      $('#selection-specific').removeClass('hidden');
      $('#selection-all').addClass('hidden');
    }
  }

  enableSelection(table_selector, row_selector) {
    var self = this;

    $(table_selector).on('click', row_selector, function (e) {
      var id = $(this).data('id');

      if (self.selected.has(id)) {
        $(this).removeClass('selected-line');
        self.selected.delete(id);
        self.manageTags.removeFromSelection(id);
        self.export.removeFromSelection(id);
        self.updateSelectedCount();
      }
      else {
        $(this).addClass('selected-line');
        self.selected.add(id);
        self.manageTags.addToSelection(id);
        self.export.addToSelection(id);
        self.updateSelectedCount();
      }
    });

    $(table_selector).on('refresh', function(e) {
      $(table_selector).find(row_selector).each(function (index) {
        var id = $(this).data('id');
        if (self.selected.has(id)) {
          $(this).addClass('selected-line');
        }
      });
    });
  }
}


class GenericSelector {

  constructor(container_selector, element_selector, form_selector) {
    this.container = $(container_selector);
    this.form = $(form_selector);
    this.selected = new Set();
    this.enableSelection(this.container, element_selector);
  }

  getSelection() {
    return Array.from(this.selected);
  }

  enableSelection(container, element_selector) {
    var self = this;
    this.form.find('.selection-specific').hide();
    this.form.find('.selection-all').show();

    container.on('click', element_selector, function (e) {

      var id = $(this).data('element-id');

      if (self.selected.has(id)) {
        $(this).removeClass('selected-element');
        self.form.find("input[value="+id+"]").remove();
        self.selected.delete(id);
        self.refreshCount();
      }
      else {
        $(this).addClass('selected-element');
        var i = $('<input name="ids" type="hidden" value="'+id+'">');
        self.selected.add(id);
        self.form.append(i);
        self.refreshCount();
      }
    });
  }

  bindCallback(button_selector, callback) {
    self = this;
    var form = this.form;
    form.on("click", button_selector, function(e) {
      e.preventDefault();
      callback($(this), form, self.container);
    });
  }

  refreshCount() {
    var self = this;
    $(self.counter_selector).text(self.selected.size);

    if (self.selected.size === 0) {
      this.form.find('.selection-specific').hide();
      this.form.find('.selection-all').show();
    } else {
      this.form.find('.selection-specific').show();
      this.form.find('.selection-all').hide();
    }
  }
}


function unlink(btn, form) {
  url = btn.data('action');
  ids = form.serializeObject();

  $.ajax({
    method: "POST",
    headers: {"Accept": "application/json"},
    contentType: "application/json",
    url: url,
    data: JSON.stringify(ids),
    success: function(data) {
      for (var i in data['deleted']) {
        $(".node-line[data-element-id='"+data['deleted'][i]+"']").remove();
      }
    },
    error: function(data) {
      notify("Error unlinking entities.", "danger");
    }
  });
}

function edit(btn, form) {
  ids = form.serializeObject()['ids'];
  url = btn.data('action');

  if (ids != undefined ) {
    var ids = [].concat(ids);
    var count = ids.length; // remove this if we're hiding the button

    if (count > 0) {

      if (count === 1) {
        defaultValue = $("tr[data-element-id="+ids[0]+"]").find("td.link-description").text();
      }
      else {
        defaultValue = "";
      }

      var newDescription = window.prompt("Change link description for "+count+" links", defaultValue);
      if (newDescription == null) {
        return;
      }

      data = {"new": {"description": newDescription}, "ids": ids};

      $.ajax({
        method: "POST",
        headers: {"Accept": "application/json"},
        contentType: "application/json",
        url: url,
        data: JSON.stringify(data),
        success: function(data) {
          for (let id of data['updated']) {
            $("tr[data-element-id="+id+"]").find("td.link-description").text(newDescription);
          }
        },
        error: function(data) {
          notify("Error editing link.", "danger");
        }
      });
    }

  }
}
