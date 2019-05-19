//
// Global Values (DataSets and Templates)
//

"use strict";

// Compile templates
var nodeTemplate = Handlebars.compile($('#graph-sidebar-node-template').html());
var nodesTemplate = Handlebars.compile($('#graph-sidebar-nodes-template').html());
var linksTemplate = Handlebars.compile($('#graph-sidebar-links-template').html());
var quickAddResult = Handlebars.compile($('#graph-quick-add-result').html());
var quickAddEmpty = Handlebars.compile($('#graph-quick-add-empty').html());
var tagsTemplate = Handlebars.compile($('#graph-sidebar-tags').html());
var noSelectionTemplate = Handlebars.compile($('#graph-sidebar-no-selection').html());
var analyticsGroupTemplate = Handlebars.compile($('#graph-sidebar-analytics-group-template').html());
var analyticsPanelTemplate = Handlebars.compile($('#graph-sidebar-analytics-panel').html());
var relatedGraphTemplate = Handlebars.compile($('#graph-sidebar-related-investigation-template').html())

Handlebars.registerPartial("links", linksTemplate);
Handlebars.registerPartial("tags", tagsTemplate);
Handlebars.registerPartial("analyticsPanel", analyticsPanelTemplate);
Handlebars.registerPartial("analyticsGroup", analyticsGroupTemplate);
var analyticsTemplate = Handlebars.compile($('#graph-sidebar-analytics-template').html());
var analyticsResultsTemplate = Handlebars.compile($('#graph-sidebar-analytics-results-template').html());

// Define default icons
var icons = {
  'Observable.Ip': flaticon('\ue005'),
  'Observable.AutonomousSystem': flaticon('\ue00b'),
  'Observable.MacAddress': flaticon('\ue005'),
  'Observable.Certificate': flaticon('\ue024'),
  'Observable.CertificateSubject': flaticon('\ue024'),
  'Observable.Hostname': flaticon('\ue01E'),
  'Observable.Url': flaticon('\ue013'),
  'Observable.Email': flaticon('\ue01A'),
  'Observable.Text': flaticon('\ue022'),
  'Observable.File': flaticon('\ue021'),
  'Observable.Hash': flaticon('\ue00e'),
  'Observable.Path': flaticon('\ue00a'),
  'Observable.Bitcoin': flaticon('\ue026'),

  'Entity.Malware': flaticon('\ue001'),
  'Entity.TTP': flaticon('\ue019'),
  'Entity.Company': flaticon('\ue002'),
  'Entity.Actor': flaticon('\ue017'),
  'Entity.Campaign': flaticon('\ue003'),
  'Indicator.Regex': flaticon('\ue015'),
};

var cssicons = {
  'Observable.Ip': 'flaticon-computer189',
  'Observable.AutonomousSystem': 'flaticon-earth213',
  'Observable.MacAddress': 'flaticon-computer189',
  'Observable.Certificate': 'flaticon-website17',
  'Observable.CertificateSubject': 'flaticon-website17',
  'Observable.Hostname': 'flaticon-server20',
  'Observable.Url': 'flaticon-links11',
  'Observable.Email': 'flaticon-message99',
  'Observable.Text': 'flaticon-typography2',
  'Observable.File': 'flaticon-text70',
  'Observable.Hash': 'flaticon-finger14',
  'Observable.Path': 'flaticon-document238',
  'Observable.Bitcoin': 'flaticon-bitcoin',
  'Entity.Malware': 'flaticon-bug24',
  'Entity.TTP': 'flaticon-maths5',
  'Entity.Company': 'flaticon-building259',
  'Entity.Campaign': 'flaticon-businessman116',
  'Entity.Actor': 'flaticon-malware',
  'Indicator.Regex': 'flaticon-magnifying-glass40',
};

//
// General purpose functions
//

function flaticon(code) {
  return {
    face: 'yetiicons',
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

function visibleLinksFilter(nodeId, field) {
  return function (links) {
    return links[field] == nodeId && links.visible;
  };
}

function invisibleLinksFilter(nodeId, field) {
  return function (links) {
    return links[field] == nodeId && !links.visible;
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

  // Also enable tooltips
  $('[data-toggle="tooltip"]').tooltip();
}

// Define Investigation logic
class Investigation {
  constructor(investigation) {
    var self = this;

    this.id = investigation._id;
    this.name = investigation.name;

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

    // Create the quick add suggestion engine
    this.quickadd_search = new Bloodhound({
      datumTokenizer: Bloodhound.tokenizers.obj.whitespace('label'),
      queryTokenizer: Bloodhound.tokenizers.whitespace,
      sufficient: 1,
      identify: function(obj) { return obj.id; },
      remote: {
        url: '/api/investigation/nodesearch/%QUERY',
        wildcard: '%QUERY',
        transform: function(results) {
          return results.map(self.buildNode);
        }
      }
    });

    // Create actions
    this.manageTags = new ManageTags('#action-managetags-template');
    this.manageTags.on('tags.added', this.addedTags.bind(this));
    this.manageTags.on('tags.removed', this.removedTags.bind(this));

    this.export = new Export('#action-export-template');

    // Setup initial data
    this.update(investigation);

    // Setup Layout options
    this.layout_directions = ["", "UD", "DU", "LR", "RL"];
    this.layout_cycle = -1;

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

      if (link.id.startsWith('local')) {
        link.active = true;
        link.color = 'red';
      }

      if (!self.hasLink(link)) {
        self.edges.add(link);
      }
      self.edges.update({id: link.id, visible: true});

      visibleEdges.delete(link.id);
    });

    visibleNodes.forEach(self.hideNode.bind(self));
    visibleEdges.forEach(self.hideLink.bind(self));
  }

  buildNode(node) {
    node.id = buildNodeId(node._cls, node._id);

    if ('value' in node) {
      node.label = node.value;
    } else {
      node.label = node.name;
    }

    node.analytics = {};
    node.links_of_interest = {};
    node.shape = 'icon';
    node.icon = icons[node._cls];
    node.cssicon = cssicons[node._cls];

    return node;
  }

  addNode(node) {
    node.id = buildNodeId(node._cls, node._id);

    var existingNode = this.nodes.get(node.id);

    if (!existingNode) {
      node = this.buildNode(node);

      this.nodes.add(node);
      this.quickadd_search.add([node]);

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

  isNodeVisible(nodeId) {
    return this.visibleNodes.get(nodeId);
  }

  addToLinksOfInterest(link, direction) {
    var inverse_direction = direction == 'to' ? 'from': 'to';
    var node = this.nodes.get(link[direction]);
    this.enrichLink(inverse_direction)(link);
    delete link['links_of_interest'];
    node.links_of_interest[direction + '-' + link[inverse_direction]] = link;
    this.nodes.update({id: node.id, links_of_interest: node.links_of_interest});
  }

  removeFromLinksOfInterest(link, direction) {
    var inverse_direction = direction == 'to' ? 'from': 'to';
    var node = this.nodes.get(link[direction]);
    delete node.links_of_interest[direction + '-' + link[inverse_direction]];
    this.nodes.update({id: node.id, links_of_interest: node.links_of_interest});
  }

  updateLinksOfInterest(link) {
    var nodeTo = this.nodes.get(link.to);
    var nodeFrom = this.nodes.get(link.from);

    if (nodeTo.visible)
      this.addToLinksOfInterest(link, 'from');

    if (nodeFrom.visible)
      this.addToLinksOfInterest(link, 'to');
  }

  addLink(link) {
    link.id = link._id;

    var existingLink = this.edges.get(link.id);

    link.first_seen = Date.parse(link.first_seen);
    link.last_seen = Date.parse(link.last_seen);
    link.history.forEach(function (history) {
      history.first_seen = Date.parse(history.first_seen);
      history.last_seen = Date.parse(history.last_seen);
      history.sources = history.sources.join(", ");
    });

    if (!existingLink) {
      if (link.description) {
        link.label = link.description;
      } else if (link.Tag) {
        link.label = link.tag;
      }

      link.from = buildNodeId(link.src.collection, link.src.id);
      link.to = buildNodeId(link.dst.collection, link.dst.id);
      link.arrows = 'to';

      this.edges.add(link);
      this.updateLinksOfInterest(link);

      return link;
    } else {
      this.edges.update({
        id: link.id,
        active: link.active,
        first_seen: link.first_seen,
        last_seen: link.last_seen,
        history: link.history
      });

      $.extend(existingLink, link);

      return existingLink;
    }
  }

  hideLink(link) {
    this.edges.update({id: link.id, visible: false});
  }

  displayLink(link) {
    this.edges.update({id: link.id, visible: true});
  }

  displayNodeId(nodeId) {
    this.nodes.update({id: nodeId, visible: true});
  }

  disableNodes(nodeIds) {
    var self = this;
    var links = [];

    nodeIds.forEach(function (nodeId) {
      var incoming = self.edges.get({filter: linksFilter(nodeId, 'to')});
      incoming.forEach(function (link) {
        self.removeFromLinksOfInterest(link, 'from');
        if (link.visible) {
          links.push(link);
        }
      });

      var outgoing = self.edges.get({filter: linksFilter(nodeId, 'from')});
      outgoing.forEach(function (link) {
        self.removeFromLinksOfInterest(link, 'to');
        if (link.visible) {
          links.push(link);
        }
      });

      self.nodes.update({id: nodeId, visible: false});
    });

    links.forEach(self.hideLink.bind(self));

    self.remove(links, nodeIds.map(dbref));
  }

  enableLinksAndNodes(links, nodeIds) {
    var self = this;

    links.forEach(function (link) {
      nodeIds.push(link.from);
      nodeIds.push(link.to);
    });

    this.linksForNodes(nodeIds, function(newLinks) {
      links = links.concat(newLinks);

      // Effectively display elements on the graph
      nodeIds.forEach(self.displayNodeId.bind(self));
      links.forEach(self.displayLink.bind(self));

      // Save them to the investigation
      self.add(links, nodeIds.map(dbref));
    });
  }

  linksForNodes(nodeIds, callback) {
    var self = this;
    var linksPromises = [false];

    // First, make sure all nodes have their links fetched
    nodeIds.forEach(function (nodeId) {
      var node = self.nodes.get(nodeId);

      if (!node.fetched) {
        linksPromises.push($.getJSON('/api/neighbors/' + node._cls + '/' + node._id));
        self.retrieveAnalyticsResults([node]);
      }
    });

    $.when.apply($, linksPromises).done(function () {
      var links = [];

      for (var i=0; i < arguments.length; i++) {
        if (arguments[i]) {
          arguments[i][0].nodes.forEach(self.addNode.bind(self));
          arguments[i][0].links.forEach(self.addLink.bind(self));
        }
      }

      // Then, see if any link needs to be displayed
      nodeIds.forEach(function (nodeId) {
        self.nodes.update({id: nodeId, fetched: true});

        var incoming = self.edges.get({filter: linksFilter(nodeId, 'to')});
        incoming.forEach(function (link) {
          self.addToLinksOfInterest(link, 'from');
          if ((!link.visible) && (self.isNodeVisible(link.from))) {
            links.push(link);
          }
        });

        var outgoing = self.edges.get({filter: linksFilter(nodeId, 'from')});
        outgoing.forEach(function (link) {
          self.addToLinksOfInterest(link, 'to');
          if ((!link.visible) && (self.isNodeVisible(link.to))) {
            links.push(link);
          }
        });
      });

      callback(links);
    });
  }

  hideLink(link) {
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
      link.links_of_interest = node.links_of_interest;
    };
  }

  sortLinks(links) {
    var result = {};

    links.forEach(function (item) {
      if (result.hasOwnProperty(item.label)) {
        result[item.label].push(item);
      } else {
        result[item.label] = new Array(item);
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

  availableAnalyticsFor(nodes) {
    var self = this;
    var results = {};

    nodes.forEach(function (node) {
      var nodeType = node._cls.split('.');
      nodeType = nodeType[nodeType.length - 1];

      self.analytics.get({
        filter: function(item) {
          return $.inArray(nodeType, item.acts_on) != -1;
        },
      }).forEach(function (analytics) {
        if (!(analytics.group in results)) {
          results[analytics.group] = {};
        }
        if (!(analytics.id in results[analytics.group]))
        {
          results[analytics.group][analytics.id] = {
            analytics: analytics,
            nodes: [node],
            nodeIds: [node._id]
          };
        }
        else {
          results[analytics.group][analytics.id].nodes.push(node);
          results[analytics.group][analytics.id].nodeIds.push(node._id);
        }
      });
    });

    return results;
  }

  forEachAnalytics(groupedAnalytics, cb) {
    function eachAnalytics(group, id) {
      cb(groupedAnalytics[group][id]);
    }

    for (var group in groupedAnalytics) {
      var cb2 = eachAnalytics.bind(null, group);
      Object.keys(groupedAnalytics[group]).forEach(cb2);
    }
  }

  displayAnalytics(nodes) {
    var availableAnalytics = this.availableAnalyticsFor(nodes);
    $('#graph-sidebar-analytics').html(analyticsTemplate({groups: availableAnalytics}));
  }

  displayAnalyticsResultsForNodes(nodes) {
    var self = this;
    var availableAnalytics = this.availableAnalyticsFor(nodes);

    self.forEachAnalytics(availableAnalytics, function (analytics) {
      analytics.nodes.forEach(function (node) {
        var resultsDiv = $('#analytics-' + analytics.analytics.id + '-' + node._id);
        var data;

        if (analytics.analytics.id in node.analytics)
          data = node.analytics[analytics.analytics.id];

        self.displayAnalyticsResults(data, resultsDiv);
      });
    });
  }

  retrieveAnalyticsResults(nodes) {
    var self = this;
    var availableAnalytics = this.availableAnalyticsFor(nodes);

    self.forEachAnalytics(availableAnalytics, function (analytics) {
      function callback(node, data) {
        var resultsDiv = $('#analytics-' + analytics.analytics.id + '-' + node._id);

        if (data) {
            data = self.saveAnalyticsResults(data);
        }

        if (resultsDiv.length) {
          self.displayAnalyticsResults(data, resultsDiv);
        }
      }

      analytics.nodes.forEach(function (node) {
        $.getJSON('/api/analytics/oneshot/' + analytics.analytics.id + '/last/' + node._id).done(callback.bind(null, node));
      });
    });
  }

  retrieveNodeNeighborsCallback(nodeId) {
    var self = this;

    return function(data) {
      data.nodes.forEach(self.addNode.bind(self));
      data.links.forEach(self.addLink.bind(self));
      self.nodes.update({id: nodeId, fetched: true});

      self.displayLinks(nodeId);
    };
  }

  retrieveNodeNeighbors(node) {
    $.getJSON('/api/neighbors/' + node._cls + '/' + node._id, this.retrieveNodeNeighborsCallback(node.id));
  }

  changeSelection(params) {
    var self = this;
    var selectedNodes = params.nodes;

    if (selectedNodes.length == 1) {
      this.selectNode(selectedNodes[0]);
    } else if (selectedNodes.length === 0) {
      $('#graph-sidebar-dynamic').html(noSelectionTemplate({}));
    } else {
      this.selectMultipleNodes(selectedNodes);
    }
  }

  selectMultipleNodes(nodeIds) {
    var self = this;
    var nodes = [];

    // Get information for each selected node
    nodeIds.forEach(function (nodeId) {
      nodes.push(self.nodes.get(nodeId));
    });

    // Update sidebar with multi-selection content
    $('#graph-sidebar-dynamic').html(nodesTemplate(nodes));

    // Update actions
    self.manageTags.changeSelection(nodeIds);
    self.manageTags.displayIn('#accordion');

    self.export.changeSelection(nodeIds);
    self.export.displayIn('#accordion');

    // Display analytics
    self.displayAnalytics(nodes);

    // Fetch nodes / display analytics results
    var unfetched = [];
    var fetched = [];
    nodes.forEach(function (node) {
      if (node.fetched) {
        fetched.push(node);
      } else {
        self.retrieveNodeNeighbors(node);
        unfetched.push(node);
      }
    });
    self.displayAnalyticsResultsForNodes(fetched);
    self.retrieveAnalyticsResults(unfetched);
  }

  fetchRelatedInv(id, ref) {
      const url = '/api/investigation/search_existence';
      const headers = new Headers();
      headers.append('Accept', 'application/json');
      headers.append('Content-Type', 'application/json');

      const body = JSON.stringify({
        id,
        ref,
      });
      const init = {
        method: 'POST',
        headers,
        body,
      };
      return fetch(url, init);
    }

  updateRelatedGraph(nodeId) {
      var self = this;

      const [ref, id] = nodeId.split('-');
      const fetchRelatedInv = this.fetchRelatedInv(id, ref);
      fetchRelatedInv
        .then((res) => {
          return res.json();
        })
        .then((results) => {
          const params = {
            investigations: results.filter(investigation => investigation._id != self.id),
          };
          $('#graph-sidebar-related-investigation').html(relatedGraphTemplate(params));
        })
        .catch((err) => {
          if (err) console.error(err);
        });
    }

  selectNode(nodeId) {
    var node = this.nodes.get(nodeId);

    // Update sidebar with content related to this node
    $('#graph-sidebar-dynamic').html(nodeTemplate(node));

    // Fetch related investigations
    this.updateRelatedGraph(nodeId);

    // Enable HighlightJS
    hljs.initHighlighting.called = false;
    hljs.initHighlighting();

    // Update actions
    this.manageTags.selectOne(nodeId);
    this.manageTags.displayIn('#accordion');

    this.export.selectOne(nodeId);
    this.export.displayIn('#accordion');

    // Display analytics
    this.displayAnalytics([node]);

    // Display links
    if (node.fetched) {
      this.displayLinks(nodeId);
      this.displayAnalyticsResultsForNodes([node]);
    } else {
      this.retrieveNodeNeighbors(node);
      this.retrieveAnalyticsResults([node]);
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

  displayAnalyticsResults(data, resultsDiv) {
    var self = this;

    resultsDiv.find('.fa-spinner').addClass('hide');
    if (data) {
      resultsDiv.find('.analytics-results').html(analyticsResultsTemplate(data));
      enablePopovers();
      resultsDiv.find('.glyphicon-refresh').removeClass('hide');
      resultsDiv.closest('.graph-sidebar-analytics').find('.graph-sidebar-show-results').removeClass('hide');
    } else {
      resultsDiv.find('.glyphicon-play').removeClass('hide');
    }
    self.updateAnalyticsLinks(resultsDiv);

    // Enable HighlightJS on raw results
    hljs.initHighlighting.called = false;
    hljs.initHighlighting();
  }

  saveAnalyticsResults(data) {
    var self = this;
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

    var node = self.nodes.get('observable-' + data.observable);
    node.analytics[data.analytics] = data;
    self.nodes.update({id: node.id, analytics: node.analytics});

    return data;
  }

  fetchAnalyticsResults(id) {
    var self = this;

    function callback(data) {
      var analyticsDiv = $('#graph-sidebar-analytics-' + id);
      var resultsDiv = $('#analytics-' + data.analytics + '-' + data.observable);
      var button = analyticsDiv.find('.graph-sidebar-run-analytics');

      if (data.status == 'finished') {
        data = self.saveAnalyticsResults(data, resultsDiv);
        self.displayAnalyticsResults(data, resultsDiv);
        button.find('.glyphicon-play').addClass('hide');
        button.find('.fa-spinner').removeClass('hide');
      } else if (data.status == 'error') {
        self.displayAnalyticsResults(data, resultsDiv);
        button.find('.glyphicon-play').addClass('hide');
        button.find('.fa-spinner').removeClass('hide');
      } else {
        setTimeout(self.fetchAnalyticsResults.bind(self, id), 1000);
      }
    }

    $.get(
      '/api/analytics/oneshot/' + id + '/status',
      {},
      callback,
      'json'
    );
  }

  runAnalytics(id, nodeId) {
    var self = this;

    // Run the analytics
    function runCallback(data) {
      var resultsId = data._id;

      self.fetchAnalyticsResults(resultsId);
    }

    $.post(
      '/api/analytics/oneshot/' + id + '/run',
      {id: nodeId},
      runCallback,
      'json'
    );

    // Give proper feedback
    var link = $('#analytics-' + id + '-' + nodeId);
    link.find('.glyphicon-play').addClass('hide');
    link.find('.glyphicon-refresh').addClass('hide');
    link.find('.fa-spinner').removeClass('hide');

    self.updateAnalyticsLinks(link);
  }

  updateAnalyticsLinks(resultsDiv) {
    var parent = resultsDiv.parents('.graph-sidebar-analytics');
    var parentLinks = parent.children('.graph-sidebar-links');
    var subresults = parent.find('.analytics-results-slider');

    parentLinks.find('.glyphicon-play').addClass('hide');
    parentLinks.find('.glyphicon-refresh').addClass('hide');
    parentLinks.find('.fa-spinner').addClass('hide');

    if (subresults.find('.fa-spinner:not(.hide)').length) {
      parentLinks.find('.fa-spinner').removeClass('hide');
    } else if (subresults.find('.glyphicon-play:not(.hide)').length) {
      parentLinks.find('.glyphicon-play').removeClass('hide');
    } else {
      parentLinks.find('.glyphicon-refresh').removeClass('hide');
    }

  }

  add(links, nodes) {
    return this.save_changes('add', links, nodes);
  }

  remove(links, nodes) {
    return this.save_changes('remove', links, nodes);
  }

  save_changes(action, links, nodes) {
    var self = this;

    var data = {
      links: links,
      nodes: nodes,
    };

    function callback(investigation) {
      self.update(investigation);
    }

    // Persist changes, and update to last version
    $.ajax({
      type: 'POST',
      url: '/api/investigation/' + action + '/' + self.id,
      data: JSON.stringify(data),
      success: callback,
      dataType: 'json',
      headers: {"Accept": "text/html"},
      contentType: 'application/json',
    });
  }

  addManualLink(data, callback) {
    var label = prompt("Label", "");

    if (label === "") {
      label = null;
    }

    data.id = "local-" + Date.now();
    data.arrows = 'to';
    data.active = true;
    data.label = label;
    data.color = 'red';

    callback(data);
    this.enableLinksAndNodes([data], []);
  }

  toggleLayout() {
    var self = this;
    var container = document.getElementById('graph-network');

    //
    // This part is kind of ugly
    // We have to use new DataSets using the same data
    // Otherwise, visjs seem to have some kind of bug after switching
    // from one layout to another.
    //
    var edges = new vis.DataSet();

    self.edges.get().forEach(function (edge) {
      edges.add(edge);
    });

    self.edges = edges;

    this.visibleEdges = new vis.DataView(this.edges, {
      filter: function(item) {
        return item.visible;
      },
    });
    //
    // End of uglyness
    //

    var data = {
      nodes: self.visibleNodes,
      edges: self.visibleEdges,
    };

    self.layout_cycle += 1;
    var direction = self.layout_directions[self.layout_cycle % 5];

    var options = {
      physics: {
        barnesHut: {
          springLength: 300,
        },
      },
      manipulation: {
        enabled: false,
        addEdge: self.addManualLink.bind(self)
      },
      interaction: {
        multiselect: true,
      }
    };

    if (direction !== '') {
      options.layout = {
        hierarchical: {
          direction: direction
        }
      };
    }

    if ((self.network !== undefined) && (self.network !== null)) {
      self.network.destroy();
      self.network = null;
    }

    self.network = new vis.Network(container, data, options);

    self.network.on('select', function(params) {
      self.changeSelection(params);
    });
  }

  addedTags(data) {
    var self = this;

    data.selection.forEach(function (nodeId) {
      if (nodeId.startsWith('observable-')) {
        var alreadyIn = [];
        var node = self.nodes.get(nodeId);

        node.tags.forEach(function (tag) {
          if (data.tags.includes(tag.name)) {
            alreadyIn.push(tag.name);
          }
        });

        data.tags.forEach(function (tag) {
          if (!alreadyIn.includes(tag)) {
            node.tags.push({'name': tag});
          }
        });

        self.nodes.update(node);
        $('#graph-sidebar-taglist-' + nodeId).html(tagsTemplate(node));
      }
    });
  }

  removedTags(data) {
    var self = this;

    data.selection.forEach(function (nodeId) {
      if (nodeId.startsWith('observable-')) {
        var newTags = [];
        var node = self.nodes.get(nodeId);

        node.tags.forEach(function (tag) {
          if (!data.tags.includes(tag.name)) {
            newTags.push(tag);
          }
        });

        node.tags = newTags;
        self.nodes.update(node);
        $('#graph-sidebar-taglist-' + nodeId).html(tagsTemplate(node));
      }
    });
  }

  selectAllNodes() {
    var self = this;

    var nodeIds = self.nodes.getIds({filter: function(item) {
      return item.visible;
    }});

    self.network.selectNodes(nodeIds);
    self.changeSelection({'nodes': nodeIds});
  }

  initGraph() {
    // create a network
    this.toggleLayout();

    // create analytics
    this.loadAnalytics();

    var self = this;

    // Define event handlers
    $('#graph-sidebar').on('click', '#graph-select-all', function(e) {
      e.preventDefault();
      self.selectAllNodes();
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-display-link', function(e) {
      var linkId = $(this).data('link');
      var link = self.edges.get(linkId);

      self.enableLinksAndNodes([link], []);
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-view-node', function(e) {
      var nodeId = $(this).data('node');
      self.selectNode(nodeId);
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-display-node', function (e) {
      var nodeId = $(this).data('node');
      self.enableLinksAndNodes([], [nodeId]);
      self.selectNode(nodeId);
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-remove-node', function (e) {
      var nodeId = $(this).data('node');
      self.disableNodes([nodeId]);
      self.selectNode(nodeId);
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-run-analytics', function(e) {
      var link = $(this);
      var id = link.data('id');
      var nodeIds = link.data('node-id').split(',');

      nodeIds.forEach(function (nodeId) {
        self.runAnalytics(id, nodeId);
      });
    });

    $('#graph-sidebar').on('click', '.graph-sidebar-show-results', function(e) {
      var resultsDiv = $(this).parents('.graph-sidebar-analytics').find('.analytics-results-slider');
      resultsDiv.removeClass('no-overflow');
      resultsDiv.addClass('slide-right');
    });

    $('#graph-sidebar').on('click', '.analytics-results-close', function(e) {
      var resultsDiv =
      $(this).parents('.analytics-results-slider');

      resultsDiv.removeClass('slide-right');
      setTimeout(function() {
        resultsDiv.addClass('no-overflow');
      }, 210);
    });

    // Allow sidebar to be resized
    var sidebar_min = 300;
    var sidebar_max = 1000;

    $('#graph-sidebar-resize').on('mousedown', function(e) {
      e.preventDefault();

      $(document).mousemove(function (e) {
        e.preventDefault();

        var x = e.pageX - $('#graph-sidebar').offset().left;

        if (x > sidebar_min && x < sidebar_max) {
          $('#graph-sidebar').css("width", x);
          $('#graph-sidebar-resize').css("left", x);
          $('#graph').css("left", x + 5);
        }
      });
    });

    $(document).mouseup(function (e) {
      $(document).unbind('mousemove');
    });

    // Renaming Investigation
    if (self.name) {
      $('#graph-sidebar-investigation-name span').text(self.name);
    }

    $('#graph-sidebar-investigation-name a').on('click', function(e) {
      e.preventDefault();

      var nameElement = $('#graph-sidebar-investigation-name span');
      var form = $('#graph-sidebar-investigation-name form');
      var input = $('#graph-sidebar-investigation-name input');
      var name = nameElement.text();

      if (name == "Unnamed Investigation") {
          input.val('');
      } else {
          input.val(name);
      }
      nameElement.addClass('hidden');
      input.removeClass('hidden');
      input.focus();

      function validateNameChange(e) {
        e.preventDefault();

        var newName = input.val();

        $.ajax({
          type: 'POST',
          url: '/api/investigation/rename/' + self.id,
          data: JSON.stringify({name: newName}),
          dataType: 'json',
          headers: {"Accept": "text/html"},
          contentType: 'application/json',
        }).fail(function (d) {
          notify('Could not save new name.', 'danger');
        });

        input.addClass('hidden');
        nameElement.text(newName);
        nameElement.removeClass('hidden unsaved');
      }

      form.on('submit', validateNameChange);
      input.focusout(validateNameChange);
    });

    // Quick Add
    $('.typeahead').typeahead({
      hint: true,
      highlight: true,
      minLength: 1
    },
    {
      displayKey: 'label',
      templates: {
        suggestion: quickAddResult,
        empty: quickAddEmpty
      },
      source: self.quickadd_search
    });

    $('.typeahead').bind('typeahead:select', function(ev, suggestion) {
      suggestion = self.addNode(suggestion);
      self.enableLinksAndNodes([], [suggestion.id]);
      $(this).typeahead('val', '');
    });

    // Add link button
    $('#graph-add-link').click(function (e) {
      e.preventDefault();
      if (self.layout_cycle % 5 === 0) {
        self.network.addEdgeMode();
      }
      else {
        notify("Link creation not available when in hierarchical layout", "warning");
      }
    });

    // Hierachical Layout
    $('#graph-hierarchical').click(function (e) {
      e.preventDefault();
      self.toggleLayout();
    });

    // Add node buttons
    $('.graph-add-node').click(function (e) {
      e.preventDefault();

      var url = $(this).attr('href');
      var value = $('.tt-input').val();

      $.get(url).done(function (html) {
        var title = $(html).find('h1').text();
        var content = $(html).find('.form-content').html();

        $('#graph-modal h4').text(title);
        $('#graph-modal .modal-body').html(content);
        $('#graph-modal #name').val(value);
        $('#graph-modal #value').val(value);

        refresh_tagfields($('#graph-modal .modal-body'));

        $('#graph-modal').modal('show');

        $('#graph-mobal-submit').off().on('click', function (e) {
          $.post(url, $('#graph-modal form').serialize()).done(function (data) {
            // Errors in the submission
            if ($(data).find('.yeti-add-node').length) {
              content = $(data).find('.form-content').html();
              $('#graph-modal .modal-body').html(content);
              refresh_tagfields($('#graph-modal .modal-body'));
            }
            // Everything fine, proceed
            else {
              var nameElt = $(data).find('#yeti-node-name');
              var id = nameElt.data('id');
              var klass = nameElt.data('class');

              $.getJSON('/api/neighbors/' + klass + '/' + id, function(result) {
                result.links.forEach(self.addLink.bind(self));
                result.nodes.forEach(self.addNode.bind(self));
                self.nodes.update({id: id, fetched: true});

                self.enableLinksAndNodes([], [buildNodeId(klass, id)]);

                $(this).typeahead('val', '');
                $('#graph-modal').modal('hide');
              });
            }
          });
        });
      });
    });

  }

}
