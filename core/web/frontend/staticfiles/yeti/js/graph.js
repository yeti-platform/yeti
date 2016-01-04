$(function() {
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

  function retrieveNodeNeighborsCallback(nodeId) {
    return function(data) {
      data.links.forEach(function(link) {
        if (!edges.get(link.id)) {
          link.arrows = 'to';
          link.length = 300;
          edges.add(link);
        }
      });

      data.nodes.forEach(function(node) {
        if (!nodes.get(node.id)) {
          node.label = node.value;
          node.shape = 'icon';
          node.icon = icons[node.type];
          node.cssicon = cssicons[node.type];
          nodes.add(node);
        }
      });

      displayLinks(nodeId);
    };
  }

  function retrieveNodeNeighbors(nodeId) {
    $.getJSON('/api/graph/neighbors/' + nodeId, retrieveNodeNeighborsCallback(nodeId));
  }

  function selectNode(nodeId) {
    var node = nodes.get(nodeId);

    // Update sidebar with content related to this node
    $('#graph-sidebar').html(nodeTemplate(node));

    if (node.fetched) {
      alert('ok');
    } else {
      retrieveNodeNeighbors(nodeId);
    }
  }

  // Compile templates
  var nodeTemplate = Handlebars.compile($('#graph-sidebar-node-template').html());
  var linksTemplate = Handlebars.compile($('#graph-sidebar-links-template').html());

  // create the observable dataset and dataview
  var nodes = new vis.DataSet([]);
  var visibleNodes = new vis.DataView(nodes, {
    filter: function(item) {
      return item.visible;
    },
  });

  // Add the first observable
  nodes.add(observable);

  // create the edges dataset and dataview
  var edges = new vis.DataSet([]);
  var visibleEdges = new vis.DataView(edges, {
    filter: function(item) {
      return item.visible;
    },
  });

  // create a network
  var container = document.getElementById('graph');
  var data = {
    nodes: visibleNodes,
    edges: visibleEdges,
  };
  var options = {};
  var network = new vis.Network(container, data, options);

  network.on('selectNode', function(params) {
    selectNode(params.nodes[params.nodes.length - 1]);
  });

  $('#graph-sidebar').on('click', '.graph-sidebar-display-link', function(e) {
    linkId = $(this).data('link');
    nodeId = $(this).data('node');

    edges.update({id: linkId, visible: true});
    nodes.update({id: nodeId, visible: true});
  });
});
