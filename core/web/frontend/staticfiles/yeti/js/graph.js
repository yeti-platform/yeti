//
// Global Values (DataSets and Templates)
//

"use strict";

// Add Handlebars helpers
Handlebars.registerHelper('equal', function(lvalue, rvalue, options) {
    if (arguments.length < 3)
        throw new Error("Handlebars Helper equal needs 2 parameters");
    if( lvalue!=rvalue ) {
        return options.inverse(this);
    } else {
        return options.fn(this);
    }
});

Handlebars.registerHelper("date", function(datetime) {
  var date = new Date(datetime);

  var month = date.getUTCMonth() + 1;
  if (month < 10) {
    month = "0" + month;
  }

  var day = date.getUTCDate();
  if (day < 10) {
    day = "0" + day;
  }

  return date.getUTCFullYear() + "-" + month + "-" + day;
});

Handlebars.registerHelper("hasMoreHistory", function(link, options) {
  if ((link.active) || ((link.history) && (link.history.length > 1))) {
    return options.fn(this);
  } else {
    return options.inverse(this);
  }
});

// Compile templates
var nodeTemplate = Handlebars.compile($('#graph-sidebar-node-template').html());
var linksTemplate = Handlebars.compile($('#graph-sidebar-links-template').html());
var analyticsTemplate = Handlebars.compile($('#graph-sidebar-analytics-template').html());

Handlebars.registerPartial("links", linksTemplate);
var analyticsResultsTemplate = Handlebars.compile($('#graph-sidebar-analytics-results-template').html());

// Define default icons
var icons = {
  'Observable.Ip': flaticon('\ue005'),
  'Observable.Hostname': flaticon('\ue01E'),
  'Observable.Url': flaticon('\ue013'),
  'Observable.Email': flaticon('\ue01A'),
  'Observable.Text': flaticon('\ue022'),
  'Observable.File': flaticon('\ue021'),
  'Observable.Hash': flaticon('\ue00e'),
  'Entity.Malware': flaticon('\ue001'),
  'Entity.TTP': flaticon('\ue019'),
  'Entity.Company': flaticon('\ue002'),
  'Indicator.Regex': flaticon('\ue015'),
};

var cssicons = {
  'Observable.Ip': 'flaticon-computer189',
  'Observable.Hostname': 'flaticon-server20',
  'Observable.Url': 'flaticon-links11',
  'Observable.Email': 'flaticon-message99',
  'Observable.Text': 'flaticon-typography2',
  'Observable.File': 'flaticon-text70',
  'Observable.Hash': 'flaticon-finger14',
  'Entity.Malware': 'flaticon-bug24',
  'Entity.TTP': 'flaticon-maths5',
  'Entity.Company': 'flaticon-building259',
  'Indicator.Regex': 'flaticon-magnifying-glass40',
};

//
// General purpose functions
//

function flaticon(code) {
  return {
    face: 'Flaticon',
    code: code,
    size: 40,
    color: '#495B6C',
  };
}

function dbref(nodeId) {
  var parts = nodeId.split('-');

  return {
    '$id': { '$oid': parts[1] },
    '$ref': parts[0],
  };
}

function buildNodeId(nodeCls, nodeId) {
  var collection = nodeCls.split('.')[0].toLowerCase();

  return collection + '-' + nodeId;
}

function linksFilter(nodeId, field) {
  return function(links) {
    return links[field] == nodeId;
  };
}

function enablePopovers() {
  $('[rel="popover"]').popover({
        container: 'body',
        html: true,
        trigger: 'hover',
        delay: {
          show: 500,
          hide: 0
        },
        content: function () {
            var clone = $($(this).data('popover-content')).clone(true).removeClass('hide');
            return clone;
        }
    }).click(function(e) {
        e.preventDefault();
    });
}

// Define Investigation logic
class Investigation {
  constructor(investigation) {
    this.id = investigation._id;
    console.log(this.id);

    // Create the nodes dataset and dataview
    this.nodes = new vis.DataSet([]);
    this.visibleNodes = new vis.DataView(this.nodes, {
      filter: function(item) {
        return item.visible;
      },
    });

    // Create the edges dataset and dataview
    this.edges = new vis.DataSet([]);
    this.visibleEdges = new vis.DataView(this.edges, {
      filter: function(item) {
        return item.visible;
      },
    });

    // Create the analytics dataset
    this.analytics = new vis.DataSet([]);

    // Setup initial data
    this.update(investigation);

    // Display graph
    this.initGraph();
  }

  update(investigation) {
    var self = this;

    var visibleNodes = new Set(self.visibleNodes.getIds());
    var visibleEdges = new Set(self.visibleEdges.getIds());

    investigation.nodes.forEach(function(node) {
      node = self.displayNode(node);
      visibleNodes.delete(node.id);
    });

    investigation.links.forEach(function(link) {
      link.from = link.fromnode;
      link.to = link.tonode;
      link.arrows = 'to';

      if (!self.hasLink(link)) {
        self.edges.add(link);
      }
      self.edges.update({id: link.id, visible: true});

      visibleEdges.delete(link.id);
    });

    visibleNodes.forEach(self.hideNode.bind(self));
    visibleEdges.forEach(self.hideLink.bind(self));
  }

  addNode(node) {
    node.id = buildNodeId(node._cls, node._id);

    var existingNode = this.nodes.get(node.id);

    if (!existingNode) {
      if ('value' in node) {
        node.label = node.value;
      } else {
        node.label = node.name;
      }

      node.shape = 'icon';
      node.icon = icons[node._cls];
      node.cssicon = cssicons[node._cls];

      this.nodes.add(node);

      return node;
    } else {
      this.nodes.update({id: node.id, context: node.context, tags: node.tags});
      return existingNode;
    }
  }

  displayNode(node) {
    node = this.addNode(node);
    this.nodes.update({id: node.id, visible: true});

    return node;
  }

  hideNode(nodeId) {
    this.nodes.update({id: node.id, visible: false});
  }

  hasLink(link) {
    var existingLink = this.edges.get(link.id);

    return existingLink;
  }

  addLink(link) {
    link.id = link._id;

    var existingLink = this.edges.get(link.id);

    if (!existingLink) {
      if (link.description) {
        link.label = link.description;
      } else if (link.Tag) {
        link.label = link.tag;
      }

      link.from = buildNodeId(link.src.collection, link.src.id);
      link.to = buildNodeId(link.dst.collection, link.dst.id);
      link.arrows = 'to';

      link.first_seen = Date.parse(link.first_seen)
      link.last_seen = Date.parse(link.last_seen)
      link.history.forEach(function (history) {
        history.first_seen = Date.parse(history.first_seen);
        history.last_seen = Date.parse(history.last_seen);
        history.sources = history.sources.join(", ");
      });

      this.edges.add(link);

      return link;
    } else {
      return existingLink;
    }
  }

  displayLink(link) {
    link = this.addLink(link);
    this.edges.update({id: link.id, visible: true});

    return link;
  }

  hideLink(linkId) {
    this.edges.update({id: link.id, visible: false});
  }

  enrichLink(nodeField) {
    var self = this;

    return function(link) {
      var node = self.nodes.get(link[nodeField]);
      link.nodeId = node.id;
      link.cssicon = node.cssicon;
      link.value = node.label;
      link.tags = node.tags;
    };
  }

  sortLinks(links) {
    var result = {};

    links.forEach(function (item) {
      if (result.hasOwnProperty(item.description)) {
        result[item.description].push(item);
      } else {
        result[item.description] = new Array(item);
      }
    });

    Object.keys(result).forEach(function(key) {
      result[key].sort(function(a, b) {
        return b.last_seen - a.last_seen;
      });
    });

    return result;
  }

  displayLinks(nodeId) {
    var incoming = this.edges.get({filter: linksFilter(nodeId, 'to')});
    incoming.forEach(this.enrichLink('from'));
    $('#graph-sidebar-links-to-' + nodeId).html(linksTemplate({links: this.sortLinks(incoming), suffix: " for"}));

    var outgoing = this.edges.get({filter: linksFilter(nodeId, 'from')});
    outgoing.forEach(this.enrichLink('to'));
    $('#graph-sidebar-links-from-' + nodeId).html(linksTemplate({links: this.sortLinks(outgoing)}));

    enablePopovers();
  }

  displayAnalytics(node) {
    var nodeType = node._cls.split('.');
    nodeType = nodeType[nodeType.length - 1];

    var availableAnalytics = this.analytics.get({
      filter: function(item) {
        return $.inArray(nodeType, item.acts_on) != -1;
      },
    });

    $('#graph-sidebar-analytics-' + node.id).html(analyticsTemplate({analytics: availableAnalytics}));
  }

  retrieveNodeNeighborsCallback(nodeId) {
    var self = this;

    return function(data) {
      data.links.forEach(self.addLink.bind(self));
      data.nodes.forEach(self.addNode.bind(self));
      self.nodes.update({id: nodeId, fetched: true});

      self.displayLinks(nodeId);
    };
  }

  retrieveNodeNeighbors(node) {
    $.getJSON('/api/neighbors/' + node._cls + '/' + node._id, this.retrieveNodeNeighborsCallback(node.id));
  }

  selectNode(nodeId) {
    var node = this.nodes.get(nodeId);

    // Update sidebar with content related to this node
    $('#graph-sidebar').html(nodeTemplate(node));

    // Enable HighlightJS
    hljs.initHighlighting.called = false;
    hljs.initHighlighting();

    // Display analytics
    this.displayAnalytics(node);

    // Display links
    if (node.fetched) {
      this.displayLinks(nodeId);
    } else {
      this.retrieveNodeNeighbors(node);
    }
  }

  refreshAnalytics() {
    var nodeId = $('#graph-sidebar-content').data('id');

    if (nodeId) {
      var node = this.nodes.get(nodeId);
      this.displayAnalytics(node);
    }
  }

  loadAnalytics() {
    var self = this;

    $.getJSON('/api/analytics/oneshot/', function(data) {
      data.forEach(function(item) {
        if ((item.enabled) && (item.available)) {
          self.analytics.add(item);
        }
      });

      self.refreshAnalytics();
    });
  }

  fetchAnalyticsResultsCallback(id, resultsId, resultsDiv, button) {
    var self = this;
    return function() {
      return self.fetchAnalyticsResults(id, resultsId, resultsDiv, button);
    };
  }

  fetchAnalyticsResults(id, resultsId, resultsDiv, button) {
    var self = this;

    function callback(data) {
      if (data.status == 'finished') {
        var links = [];

        data.results.nodes.forEach(self.addNode.bind(self));
        data.results.links.forEach(function(link) {
          link = self.addLink(link);

          if (link.src.id == data.observable) {
            self.enrichLink('to')(link);
            links.push(link);
          } else if (link.dst.id == data.observable) {
            self.enrichLink('from')(link);
            links.push(link);
          }
        });

        data.links = self.sortLinks(links);
        resultsDiv.html(analyticsResultsTemplate(data));
        enablePopovers();
        button.removeClass('glyphicon-spinner');

        // Enable HighlightJS on raw results
        hljs.initHighlighting.called = false;
        hljs.initHighlighting();
      } else if (data.status == 'error') {
        resultsDiv.html(analyticsResultsTemplate(data));
        button.removeClass('glyphicon-spinner');
      } else {
        setTimeout(self.fetchAnalyticsResultsCallback(id, resultsId, resultsDiv, button), 1000);
      }
    }

    $.get(
      '/api/analytics/oneshot/' + resultsId + '/status',
      {},
      callback,
      'json'
    );
  }

  runAnalytics(id, nodeId, resultsDiv, progress) {
    var self = this;

    function runCallback(data) {
      var resultsId = data._id;

      self.fetchAnalyticsResults(id, resultsId, resultsDiv, progress);
    }

    $.post(
      '/api/analytics/oneshot/' + id + '/run',
      {id: nodeId},
      runCallback,
      'json'
    );
  }

  enableLink(link) {
    var self = this;

    var data = {
      links: [link],
      nodes: [dbref(link.from), dbref(link.to)],
    };

    // Effectively display elements on the graph
    this.nodes.update([{id: link.from, visible: true}, {id: link.to, visible: true}]);
    this.edges.update({id: link.id, visible: true});

    function callback(investigation) {
      self.update(investigation);
    };

    // Persist changes, and update to last version
    $.ajax({
      type: 'POST',
      url: '/api/investigation/add/' + self.id,
      data: JSON.stringify(data),
      success: callback,
      dataType: 'json',
      contentType: 'application/json',
    });
  }

  initGraph() {
    // create a network
    var container = document.getElementById('graph');
    var data = {
      nodes: this.visibleNodes,
      edges: this.visibleEdges,
    };
    var options = {
      physics: {
        barnesHut: {
          springLength: 300,
        },
      },
    };
    var network = new vis.Network(container, data, options);

    // create analytics
    this.loadAnalytics();

    var self = this;

    // Define event handlers
    network.on('selectNode', function(params) {
      self.selectNode(params.nodes[params.nodes.length - 1]);
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-display-link', function(e) {
      var linkId = $(this).data('link');
      var link = self.edges.get(linkId);

      self.enableLink(link);
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-view-node', function(e) {
      var nodeId = $(this).data('node');
      self.selectNode(nodeId);
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-run-analytics', function(e) {
      var button = $(this);

      var id = button.data('id');
      var nodeId = button.parents('#graph-sidebar-content').data('id');
      nodeId = nodeId.split('-');
      nodeId = nodeId[nodeId.length - 1];
      var resultsDiv = button.parent().prev();

      button.addClass('glyphicon-spinner');

      self.runAnalytics(id, nodeId, resultsDiv, button);
    });
  }

}
