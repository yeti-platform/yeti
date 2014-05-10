window.onkeydown=function(e){
  if(e.keyCode==32){
   return false;
  }
};




// declare useful global vars
var radiusScale, 
	color, 
	width, 
	height, 
	nodes, 
	links, 
	shiftKey, 
	force, 
	svg, 
	brush, 
	node, 
	link,
	link_labels,
	curved_links

// rescale g
function rescale() {
	if (!shiftKey) {
	  trans=d3.event.translate;
	  scale=d3.event.scale;
	  svg.attr("transform",
	      "translate(" + trans + ")" +
	      " scale(" + scale + ")");
	}
}


function initialize_graph() {
		 radiusScale = 
		      d3.scale.log()
			  .domain([1, 20])
			  .range([1, 15]);

		 color = d3.scale.category10();
		 
		 width = $('.graph').width();
         height = window.innerHeight - 100;

		$('div.data').height(height);
		$('div.data').width($(window).width()-width-20);

		 nodes = []
		 links = []

		 link_labels = false
		 curved_links = false

		 force = d3.layout.force()
		    .nodes(nodes)
		    .links(links)
		    .gravity(0.05)
		    .charge(-100)
		    .friction(0.8)
		    .theta(0.99)
		    .linkDistance(70)
		    .size([width, height])
		    .on("tick", tick);

		 zoom_scale = d3.select(".graph").append("svg")
		    .attr("width", width)
		    .attr("height", height)
		    .attr("pointer-events", "all")
		 
		 svg = zoom_scale.append('g') // this will catch our events
				 // .call(d3.behavior.zoom().on("zoom", rescale))
			  //    .on("dblclick.zoom", null)
			     .attr('id', 'zoom')
			     .append('g') // this will contain the graph

		  d3.select('body')
		    .attr("tabindex", 1)
		    .on("keydown.brush", keydown)
		    .on("keyup.brush", keyup)
		    .each(function() { this.focus(); });

		 brush = svg.append("g")
		    .datum(function() { return {selected: false, previouslySelected: false}; })
		    .attr("class", "brush");

		 // make sure graph is resized when clicking on the graph link


		 node = svg.selectAll(".node")
		    link = svg.selectAll(".link");

		 // graph controls
		 console.log($("#curved-links"))	
   

}