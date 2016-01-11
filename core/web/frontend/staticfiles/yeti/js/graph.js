//
// Global Values (DataSets and Templates)
//

// Compile templates
var nodeTemplate = Handlebars.compile($('#graph-sidebar-node-template').html());
var linksTemplate = Handlebars.compile($('#graph-sidebar-links-template').html());
var analyticsTemplate = Handlebars.compile($('#graph-sidebar-analytics-template').html());

// Create the nodes dataset and dataview
var nodes = new vis.DataSet([]);
var visibleNodes = new vis.DataView(nodes, {
  filter: function(item) {
    return item.visible;
  },
});

// Create the edges dataset and dataview
var edges = new vis.DataSet([]);
var visibleEdges = new vis.DataView(edges, {
  filter: function(item) {
    return item.visible;
  },
});

// Create the analytics dataset
var analytics = new vis.DataSet([]);

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
// Functions
//

function flaticon(code) {
  return {
    face: 'Flaticon',
    code: code,
    size: 40,
    color: '#495B6C',
  };
}

function buildNodeId(nodeCls, nodeId) {
  return nodeCls.replace('.', '-') + '-' + nodeId;
}

function addNode(node) {
  node.id = buildNodeId(node._cls, node._id);

  var existingNode = nodes.get(node.id);

  if (!existingNode) {
    if ('value' in node) {
      node.label = node.value;
    } else {
      node.label = node.name;
    }

    node.shape = 'icon';
    node.icon = icons[node._cls];
    node.cssicon = cssicons[node._cls];

    nodes.add(node);

    return node;
  } else {
    return existingNode;
  }
}

function addLink(link) {
  link.id = link._id;

  var existingLink = edges.get(link.id);

  if (!existingLink) {
    if (link.description) {
      link.label = link.description;
    } else if (link.Tag) {
      link.label = link.tag;
    }

    link.from = buildNodeId(link.src.cls, link.src.id);
    link.to = buildNodeId(link.dst.cls, link.dst.id);
    link.arrows = 'to';
    edges.add(link);

    return link;
  } else {
    return existingLink;
  }
}

function displayNode(node) {
  node = addNode(node);
  nodes.update({id: node.id, visible: true});

  return node;
}

function linksFilter(nodeId, field) {
  return function(links) {
    return links[field] == nodeId;
  };
}

function enrichLink(nodeField) {
  return function(link) {
    var node = nodes.get(link[nodeField]);
    link.nodeId = node.id;
    link.cssicon = node.cssicon;
    link.value = node.label;
    link.tags = node.tags;
  };
}

function displayLinks(nodeId) {
  var incoming = edges.get({filter: linksFilter(nodeId, 'to')});
  incoming.forEach(enrichLink('from'));
  $('#graph-sidebar-links-to-' + nodeId).html(linksTemplate({links: incoming}));

  var outgoing = edges.get({filter: linksFilter(nodeId, 'from')});
  outgoing.forEach(enrichLink('to'));
  $('#graph-sidebar-links-from-' + nodeId).html(linksTemplate({links: outgoing}));
}

function displayAnalytics(node) {
  nodeType = node._cls.split('.');
  nodeType = nodeType[nodeType.length - 1];

  var availableAnalytics = analytics.get({
    filter: function(item) {
      return item.acts_on == nodeType;
    },
  });

  $('#graph-sidebar-analytics-' + node.id).html(analyticsTemplate({analytics: availableAnalytics}));
}

function retrieveNodeNeighborsCallback(nodeId) {
  return function(data) {
    data.links.forEach(addLink);
    data.nodes.forEach(addNode);
    nodes.update({id: nodeId, fetched: true});

    displayLinks(nodeId);
  };
}

function retrieveNodeNeighbors(node) {
  $.getJSON('/api/neighbors/' + node._cls + '/' + node._id, retrieveNodeNeighborsCallback(node.id));
}

function selectNode(nodeId) {
  var node = nodes.get(nodeId);

  // Update sidebar with content related to this node
  $('#graph-sidebar').html(nodeTemplate(node));

  // Display analytics
  displayAnalytics(node);

  // Display links
  if (node.fetched) {
    displayLinks(nodeId);
  } else {
    retrieveNodeNeighbors(node);
  }
}

function refreshAnalytics() {
  var nodeId = $('#graph-sidebar-content').data('id');

  if (nodeId) {
    var node = nodes.get(nodeId);
    displayAnalytics(node);
  }
}

function loadAnalytics() {
  $.getJSON('/api/analytics/oneshot', function(data) {
    data.forEach(function(item) {
      if (item.enabled) {
        analytics.add(item);
      }
    });

    refreshAnalytics();
  });
}

function fetchAnalyticsResultsCallback(name, resultsId, resultsDiv, button) {
  return function() {
    return fetchAnalyticsResults(name, resultsId, resultsDiv, button);
  };
}

function fetchAnalyticsResults(name, resultsId, resultsDiv, button) {
  function callback(data) {
    if (data.status == 'finished') {
      var links = [];

      data.results.nodes.forEach(addNode);
      data.results.links.forEach(function(link) {
        link = addLink(link);

        if (link.src.id == data.observable) {
          enrichLink('to')(link);
          links.push(link);
        } else if (link.dst.id == data.observable) {
          enrichLink('from')(link);
          links.push(link);
        }
      });

      resultsDiv.html(linksTemplate({links: links}));
      button.removeClass('glyphicon-spinner');
    } else {
      setTimeout(fetchAnalyticsResultsCallback(name, resultsId, resultsDiv, button), 1000);
    }
  }

  $.post(
    '/api/analytics/oneshot/' + name + '/status',
    {id: resultsId},
    callback,
    'json'
  );
}

function runAnalytics(name, nodeId, resultsDiv, progress) {
  function runCallback(data) {
    var resultsId = data._id;

    fetchAnalyticsResults(name, resultsId, resultsDiv, progress);
  }

  $.post(
    '/api/analytics/oneshot/' + name + '/run',
    {id: nodeId},
    runCallback,
    'json'
  );
}

// Compile templates
var nodeTemplate = Handlebars.compile($('#graph-sidebar-node-template').html());
var linksTemplate = Handlebars.compile($('#graph-sidebar-links-template').html());
var analyticsTemplate = Handlebars.compile($('#graph-sidebar-analytics-template').html());

function initGraph() {
  // create a network
  var container = document.getElementById('graph');
  var data = {
    nodes: visibleNodes,
    edges: visibleEdges,
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
  loadAnalytics();

  // Define event handlers
  network.on('selectNode', function(params) {
    selectNode(params.nodes[params.nodes.length - 1]);
  });

  $('#graph-sidebar').on('click', '.graph-sidebar-display-link', function(e) {
    linkId = $(this).data('link');
    link = edges.get(linkId);

    nodes.update([{id: link.from, visible: true}, {id: link.to, visible: true}]);
    edges.update({id: linkId, visible: true});
  });

  $('#graph-sidebar').on('click', '.graph-sidebar-view-node', function(e) {
    nodeId = $(this).data('node');
    selectNode(nodeId);
  });

  $('#graph-sidebar').on('click', '.graph-sidebar-run-analytics', function(e) {
    button = $(this);

    name = button.data('name');
    nodeId = button.parents('#graph-sidebar-content').data('id');
    nodeId = nodeId.split('-');
    nodeId = nodeId[nodeId.length - 1];
    resultsDiv = button.parent().prev();

    button.addClass('glyphicon-spinner');

    runAnalytics(name, nodeId, resultsDiv, button);
  });
}
