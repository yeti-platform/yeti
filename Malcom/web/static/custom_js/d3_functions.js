function nudge(dx, dy) {
 if (shiftKey)
    coef = 40
  else
    coef = 4
     sel = d3.selectAll('.selected').data()
      for (var i in sel) {
        sel[i].px += coef*dx
        sel[i].py += coef*dy
        sel[i].x += coef*dx
        sel[i].y += coef*dy
        sel[i].fixed = true;   
      }

    tick(); // this is the key to make it work together with updating both px,py,x,y on d !
      force.resume();

}

function getneighbors() {
  datas = d3.selectAll('.selected').data()
  ids = []
  for (var i in datas) {
    ids.push({'name': '_id', 'value': datas[i]._id.$oid})
  }
  // url = '/neighbors/'+id;
  // console.log(url);
  console.log($.param(ids))
  $.ajax({
    type: 'get',
    url: url_static_prefix+'/neighbors',
    dataType: 'json',
    data: ids,
    beforeSend: function(data) {
      $(".graph").css('opacity', 0.1)
      spinner = $("#loading-spinner")
      spinner.css('position', 'absolute');
      spinner.css('top', height/2);
      spinner.css('left', width/2);
      spinner.toggleClass('show')
      
    },
    success: function(data) {
      $(".graph").css('opacity', 1)
      console.log(data)
      spinner.toggleClass('show')
      push_nodes(data.nodes)
      push_links(data.edges)
      if (data.msg == "TOO_MANY_ELEMENTS") {
        display_message('Your request yielded too many results. Try to request simpler neighbors')
      }
      start();  
    }

  })
  
}

function display_message(text) {
  message = $('<div class="alert alert-warning"><button type="button" class="close" data-dismiss="alert">×</button>'+text+'</div>')
  $("#message").empty()
  $("#message").append(message)
}

function getevil() {
  datas = d3.selectAll('.selected').data()
  ids = []
  for (var i in datas) {
    ids.push({'name': '_id', 'value': datas[i]._id.$oid})
  }
  // url = '/neighbors/'+id;
  // console.log(url);
  console.log($.param(ids))
  $.ajax({
    url: url_static_prefix+'/evil',
    dataType: 'json',
    data: ids,
    success: function(data) {
      console.log(data)
    push_nodes(data.nodes)
    push_links(data.edges)

    start();  
    }

  })
  
}

function unfix() { // unfixes and deselects selected ndoes
  sel = d3.selectAll('.selected')
  seldata = sel.data()
  for (var i in seldata) {
    seldata[i].selected = false
    seldata[i].fixed = false
  }
  sel.classed('selected', false)
  tick();
  force.resume();
}

function hide_sniffer_nodes() { // hides nodes making them transparent
  sel = d3.selectAll('.selected')
  seldata = sel.data()
  hide_nodes = []
  show_nodes = []
  sel.classed('dim', function(d) {
    d.hidden = !(d.hidden == true)
    if (d.hidden) {
      hide_nodes.push(d._id.$oid);
    }
    else {
      show_nodes.push(d._id.$oid);
    }
    return d.hidden
  })

  // update link visibility

  link.classed('dim', function (d) {
    hidden_nodes = node.filter(function (p) {
      if (p._id == d.src || p._id == d.dst) {
          if (p.hidden == false || (typeof p.hidden == 'undefined'))
            return false;
          else {
            return true;
          }
        }
    })
    return (hidden_nodes[0].length > 0)
  })

}

function keydown() {
  if (!d3.event.metaKey) switch (d3.event.keyCode) {
    case 38: nudge( 0, -1); break;             // UP
    case 40: nudge( 0, +1); break;             // DOWN
    case 37: nudge(-1,  0); break;             // LEFT
    case 39: nudge(+1,  0); break;             // RIGHT
    case 85: unfix(); break;                   // u
    case 72: hide_sniffer_nodes(); break;      // h
    case 32: getneighbors(); break;            // space
    case 69: getevil(); break;            // space
  }
  shiftKey = d3.event.shiftKey || d3.event.metaKey;
}

function keyup() {
  shiftKey = d3.event.shiftKey || d3.event.metaKey;
}

function resize() {
    width = $('.graph').width();
    height = window.innerHeight - 150;
    $('.graph').height(height)
    svg.attr("width", width).attr("height", height);
    brush.attr('width', width).attr('height', height);
    force.size([width, height]).resume();

    brush.call(d3.svg.brush()
            .x(d3.scale.identity().domain([0, width]))
            .y(d3.scale.identity().domain([0, height]))
            .on("brushstart", function(d) {
              node.each(function(d) { 
                d.previouslySelected = shiftKey && d.selected; 
              });
            })
            .on("brush", function() {
              var extent = d3.event.target.extent();
              node.classed("selected", function(d) {
                d.selected = d.previouslySelected ^
                    (extent[0][0] <= d.x && d.x < extent[1][0]
                    && extent[0][1] <= d.y && d.y < extent[1][1]);
                return d.selected;
              });
            })
            .on("brushend", function() {
              d3.event.target.clear();
              d3.select(this).call(d3.event.target);
            }));
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
     edges[i].dst = edges[i].target._id

     links.push(edges[i])
     ids_edges.push(edges[i]._id.$oid)
     }
   }
}




function start() {

  function dragmove(d, i) {

    //console.log('dragmove')
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
      //console.log('dragend')
      d.fixed = true; // of course set the node to fixed so the force doesn't include the node in its auto positioning stuff
      tick();
      force.resume();
  }


  //update nodes
  upd_nodes = svg.selectAll('g').selectAll('circle')
              .attr('r', function (d){
                r = radiusScale(links.filter(function (dd) {
                	if (dd.target._id == null)
                		return (nodes[dd.target]._id.$oid == d._id.$oid);
                	else
                  		return (dd.target._id.$oid == d._id.$oid);
                }).length+2);
                d.radius = r;
                return r;
              })
            svg.selectAll('g').attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
              

  //select links
  link = link.data(force.links(), function(d) { return d._id.$oid })

  link.enter().insert('line', '.node')

  /* 

  Links and lines separated  */

  l = link.enter().insert("line", ".node")
    .attr("class", "link")
    .attr("marker-end", function(d) { return "url(#arrow)"; })
    .attr("id", function(d) {return d._id.$oid })
    .style("stroke", function(d) { return color(d.attribs); })

  // text on links
   path_text = svg.selectAll(".path-text").data(force.links(), function (d) { return d._id.$oid });   
  // path_text.enter().append('svg:text').attr('class','path-text').text(function (d) {return d.attribs})


  // l = link.enter().append('svg:g').attr('class', 'link-container')
  // lines = l.append('line', '.node') .attr("class", "link")
  //   .attr("marker-end", function(d) { return "url(#arrow)"; })
  //   .attr("id", function(d) {return d._id.$oid })
  //   .style("stroke", function(d) { return color(d.attribs); })

  //path_text = l.append("text").attr('class', 'path-text').text(function(d) { return d.attribs })

  // remove old links
  link.exit().remove();

  // select nodes
  node = node.data(force.nodes(), function (d) { return d._id.$oid;});

  // drag handler

  var node_drag = d3.behavior.drag()
        .on("drag", dragmove)
        .on("dragend", dragend);

  
  
  // create new svg:g
  n = node.enter().append("svg:g")
    .attr("class", "node").call(node_drag)
    .attr("id", function (d) { return d._id.$oid })

  // append circles
  n.append("circle")
     .attr('r', function (d){
                r = radiusScale(links.filter(function (dd) {
                	if (dd.target._id == null)
                		return (nodes[dd.target]._id.$oid == d._id.$oid);
                	else
                  		return (dd.target._id.$oid == d._id.$oid);
                }).length+2)
                d.radius = r
                return r;
              })
     .attr('class', function (d) { return d.type } )

     .on("mousedown", function (d) { // this is what happens when we mousedown on a node
          //console.log('mousedown')

          if (!d.selected) {
            if (!shiftKey) {
              node.classed('selected', function(p) { return p.selected = false; }) // deselect all others
            }
            d3.select(this.parentNode).classed("selected", true);
            d.selected = true
          }
          
     })
     .on("click", function(d){
          //console.log('click')
          
     })
     .on('mouseover', function(d){
          //console.log('mouseover')
          display_data(d)
      })

  // append text
  n.append("text")
      .attr("dx", 12)
      .attr("dy", ".35em")
      .text(function(d) { 
        return d['value'] 
      });

  // remove old nodes
  node.exit().remove();

  resize()
  d3.select(window).on("resize", resize);

  force.start();


}

function tick(e) {

 // if (e != undefined) {
 //    var k = 6 * e.alpha;
 //      links.forEach(function(d, i) {
 //        d.source.y += k;
 //        d.target.y -= k;
 //      });
 //  }

  node.attr("transform", function(d) { 
    d.x = Math.max(5, Math.min(width - 5, d.x));
    d.y = Math.max(5, Math.min(height - 5, d.y));
    return "translate(" + d.x + "," + d.y + ")";
  }); 

  node.attr()

  link.attr("x1", function(d) { return Math.max(5, Math.min(width - 5, d.source.x)); })
      .attr("y1", function(d) { return Math.max(5, Math.min(height - 5, d.source.y)); })
      .attr("x2", function(d) { return Math.max(5, Math.min(width - 5, d.target.x)); })
      .attr("y2", function(d) { return Math.max(5, Math.min(height - 5, d.target.y)); });

// we can adjust link length from here

    path_text.attr("transform", function(d) 
    {
      var dx = (d.target.x - d.source.x),
      dy = (d.target.y - d.source.y);
      var dr = Math.sqrt(dx * dx + dy * dy);
      var sinus = dy/dr;
      var cosinus = dx/dr;
      var l = dr-50
      var offset = ((1 - (l / dr )) / 2);

      var x=(d.source.x + (dx)*(offset));
      var y=(d.source.y + (dy)*(offset));
      //return "translate(" + x + "," + y + ")";
      return "translate(" + x + "," + y + ") matrix("+cosinus+", "+sinus+", "+-sinus+", "+cosinus+", 0 , 0)";
    });
}
