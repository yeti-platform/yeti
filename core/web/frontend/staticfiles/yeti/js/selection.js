class SelectionManager {
  constructor() {
    this.selected = new Set();
    this.enableSelection();
    this.enableActions();
  }

  reset() {
    this.selected = new Set();
    this.updateSelectedCount();
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

  enableSelection() {
    var self = this;

    $('#observables').on('click', '.node-line', function (e) {
      var id = $(this).data('id');

      if (self.selected.has(id)) {
        $(this).removeClass('selected-line');
        self.selected.delete(id);
        self.updateSelectedCount();
      }
      else {
        $(this).addClass('selected-line');
        self.selected.add(id);
        self.updateSelectedCount();
      }
    });
  }

  enrichForm(form) {
    var self = this;
    var idsDiv = form.find('.selection-ids');

    idsDiv.html('');
    if (self.selected.size === 0) {
      idsDiv.append("<input type='hidden' name='query' value='" + JSON.stringify(build_params($('.yeti-crud'))) + "' />");
    }
    else {
      for (let id of self.selected) {
        idsDiv.append("<input type='hidden' name='ids' value='" + id + "' />");
      }
    }
  }

  enableActions() {
    var self = this;

    $('.selection-form').on('submit', function (e) {
      self.enrichForm($(this));
    });

    $('.selection-tags-action').on('click', function (e) {
      e.preventDefault();

      var url = $(this).data('action');
      var form = $(this).closest('form');
      var spinner = $(this).find('span');
      spinner.removeClass('hidden');

      self.enrichForm(form);
      $.post(url, form.serialize()).done(function (data) {
        refresh_table($('.yeti-crud'));
        spinner.addClass('hidden');
        self.reset();
      });
    })
  }
}
