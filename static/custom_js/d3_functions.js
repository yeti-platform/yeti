function nudge(dx, dy) {
  node.filter(function(d) { return d.selected; })
      .attr("cx", function(d) { return d.x += dx; })
      .attr("cy", function(d) { return d.y += dy; })

  link.filter(function(d) { return d.source.selected; })
      .attr("x1", function(d) { return d.source.x; })
      .attr("y1", function(d) { return d.source.y; });

  link.filter(function(d) { return d.target.selected; })
      .attr("x2", function(d) { return d.target.x; })
      .attr("y2", function(d) { return d.target.y; });

  d3.event.preventDefault();
}

function keydown() {
  if (!d3.event.metaKey) switch (d3.event.keyCode) {
    case 38: nudge( 0, -1); break; // UP
    case 40: nudge( 0, +1); break; // DOWN
    case 37: nudge(-1,  0); break; // LEFT
    case 39: nudge(+1,  0); break; // RIGHT
  }
  shiftKey = d3.event.shiftKey || d3.event.metaKey;
}

function keyup() {
  shiftKey = d3.event.shiftKey || d3.event.metaKey;
}

function resize() {
    width = window.innerWidth - 400;//400;
    height = window.innerHeight - 100;
    $('.graph').width(width).height(height)
    svg.attr("width", width).attr("height", height);
    force.size([width, height]).resume();
}

function add_nodes(new_node) {
  push_nodes(new_node);
  start();
}

function push_nodes(new_nodes) {
  ids = []
  $(".node").each(function(index, value){
    ids.push(value.id)
  })
   for (var i in new_nodes) {
    
    if (ids.indexOf(new_nodes[i]._id.$oid) == -1) {
      
      new_nodes[i].x = Math.random()*width;
      new_nodes[i].y = Math.random()*height;

     nodes.push(new_nodes[i])
     ids.push(new_nodes[i]._id.$oid)
     }
   } 
}

function push_links(edges) {
  ids_edges = []
  $(".link").each(function(index, value){
    ids_edges.push(value.id)
  })

  ids_nodes = []
  for (var i in nodes) {
    ids_nodes.push(nodes[i]._id.$oid);
  }

   for (var i in edges) {
    oid = edges[i]._id.$oid
    src_oid = edges[i].src.$oid
    dst_oid = edges[i].dst.$oid

    if (ids_edges.indexOf(oid) == -1 && ids_nodes.indexOf(src_oid) != -1 && ids_nodes.indexOf(dst_oid) != -1) {

     edges[i].source = nodes[ids_nodes.indexOf(src_oid)]
     edges[i].target = nodes[ids_nodes.indexOf(dst_oid)]
     edges[i].src = edges[i].source._id
     edges[i].src = edges[i].target._id


     links.push(edges[i])
     ids_edges.push(edges[i]._id.$oid)
     }
   }
}

function getneighbors(id, mouse) {

  url = '/neighbors/'+id;
  console.log(url);

  $.getJSON(url, function(data) {

    push_nodes(data.nodes)
    push_links(data.edges)

    start();

  });
}


function start() {

  //update nodes
  upd_nodes = svg.selectAll('g').selectAll('circle')
              .attr('r', function (d){
                return radiusScale(links.filter(function (dd) {
                	if (dd.target._id == null)
                		return (nodes[dd.target]._id.$oid == d._id.$oid);
                	else
                  		return (dd.target._id.$oid == d._id.$oid);
                }).length+2);
              })
            svg.selectAll('g').attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
              

  //select links
  link = link.data(force.links(), function(d) { return d._id.$oid })

  // create new links
  link.enter().insert("line", ".node")
    .attr("class", "link")
    .attr("marker-end", function(d) { return "url(#arrow)"; })
    .attr("id", function(d) {return d._id.$oid })
    .style("stroke", function(d) { return color(d.attribs); })


  // remove old links
  link.exit().remove();

  // select nodes
  node = node.data(force.nodes(), function (d) { return d._id.$oid;});

  // drag handler

  var node_drag = d3.behavior.drag()
        .on("drag", dragmove)
        .on("dragend", dragend);

  function dragmove(d, i) {

      sel = d3.selectAll('.selected').data()
      for (var i in sel) {
        sel[i].px += d3.event.dx;
        sel[i].py += d3.event.dy;
        sel[i].x += d3.event.dx;
        sel[i].y += d3.event.dy;
        sel[i].fixed = true;   
      }

      tick(); // this is the key to make it work together with updating both px,py,x,y on d !
      force.resume();
  }

  function dragend(d, i) {
      d.fixed = true; // of course set the node to fixed so the force doesn't include the node in its auto positioning stuff
      tick();
      force.resume();
  }
  
  // create new svg:g
  n = node.enter().append("svg:g")
    .attr("class", "node").call(node_drag)
    .attr("id", function (d) { return d._id.$oid })

  // append circles
  n.append("circle")
      .attr('r', function (d){
                return radiusScale(links.filter(function (dd) {
                	if (dd.target._id == null)
                		return (nodes[dd.target]._id.$oid == d._id.$oid);
                	else
                  		return (dd.target._id.$oid == d._id.$oid);
                }).length+2);
              })
      .attr('class', function (d) { console.log(d.type); return d.type } )
      .on("mousedown", function (d) {
         d.fixed = true;
         d3.select(this).classed("sticky", true);
         d3.select(this.parentNode).classed("selected", !d3.select(this).classed("selected"));
     })
     .on("click", function(d){
      if (d.fixed == true) {
          d.fixed = false
          d3.select(this).classed("sticky", false)
        }

      getneighbors(d._id.$oid, d3.mouse(this))

     })
     .on('mouseover', function(d){display_data(d)})

  // append text
  n.append("text")
      .attr("dx", 12)
      .attr("dy", ".35em")
      .text(function(d) { 
        if (d['type'] == 'as') {
          return d['as_name'] + " ("+d['country']+")"
        }
        return d['value'] 
      });

  // remove old nodes
  node.exit().remove();

  // text on links
  path_text = svg.selectAll(".path-text").data(force.links(), function(d) { return d._id.$oid });   
  
  
  resize()
  d3.select(window).on("resize", resize);

  force.start();
}

function tick(e) {

  node.attr("transform", function(d) { 
  	return "translate(" + Math.max(5, Math.min(width - 5, d.x)) + "," + Math.max(5, Math.min(height - 5, d.y)) + ")"; 
 });

  link.attr("x1", function(d) { return Math.max(5, Math.min(width - 5, d.source.x)); })
      .attr("y1", function(d) { return Math.max(5, Math.min(height - 5, d.source.y)); })
      .attr("x2", function(d) { return Math.max(5, Math.min(width - 5, d.target.x)); })
      .attr("y2", function(d) { return Math.max(5, Math.min(height - 5, d.target.y)); });


 
    path_text.attr("transform", function(d) 
    {
      var dx = (d.target.x - d.source.x),
      dy = (d.target.y - d.source.y);
      var dr = Math.sqrt(dx * dx + dy * dy);
      var sinus = dy/dr;
      var cosinus = dx/dr;
      var l = d.attribs.length
      var offset = (1 - (l / dr )) / 2;
      var x=(d.source.x + dx*offset);
      var y=(d.source.y + dy*offset);
      //return "translate(" + dx + "," + dy + ")";
      return "translate(" + x + "," + y + ") matrix("+cosinus+", "+sinus+", "+-sinus+", "+cosinus+", 0 , 0)";
    });
}
