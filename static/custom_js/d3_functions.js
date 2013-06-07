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
      // new_nodes[i].x = width/2//nodes[0].x
      // new_nodes[i].y = height/2//nodes[0].y
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

  $.getJSON('/neighbors/'+id, function(data) {

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
              // .attr('y', function(d) { d.y = height / 2; return d.y})

  //select links
  link = link.data(force.links(), function(d) { return d._id.$oid })

  // create new links
  link.enter().insert("line", ".node")
    .attr("class", "link")
    .attr("id", function(d) {return d._id.$oid })
    .style("stroke", function(d) { return color(d.attribs); })


  // remove old links
  link.exit().remove();


  // select nodes
  node = node.data(force.nodes(), function (d) { return d._id.$oid;});
  
  // create new svg:g
  n = node.enter().append("svg:g")
    .attr("class", "node").call(force.drag)
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
      .style('fill', function (d) { return color(d.type) } )
      .style("stroke", function (d) { return d3.rgb(color(d.type)).darker(); })

      .on("mousedown", function (d) {
         d.fixed = true;
         d3.select(this).classed("sticky", true);
     })
     .on("click", function(d){
      if (d.fixed == true) {
          d.fixed = false
          d3.select(this).classed("sticky", false)
        }

      getneighbors(d._id.$oid, d3.mouse(this))

     })
     .on('mouseover', function(d){display_data(d)});

  // append text
  n.append("text")
      .attr("dx", 12)
      .attr("dy", ".35em")
      .text(function(d) { 
        if (d['type'] == 'as') {
          return d['as_name'] + " ("+d['country']+")"
        }
        return d[d['type']] 
      });

  // remove old nodes
  node.exit().remove();

  path_text = svg.selectAll(".path-text").data(force.links(), function(d) { return d._id.$oid });   
  
  // text on links

  //path_text.enter().append("svg:text").attr("class","path-text").text(function(d) { return d.attribs; });

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
