
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
	link

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
		    

		 force = d3.layout.force()
		    .nodes(nodes)
		    .links(links)
		    .charge(-400)
		    .friction(0.8)
		    .linkDistance(120)
		    .size([width, height])
		    .on("tick", tick);

		 svg = d3.select(".graph").append("svg")
		    .attr("width", width)
		    .attr("height", height);

		  d3.select('body')
		    .attr("tabindex", 1)
		    .on("keydown.brush", keydown)
		    .on("keyup.brush", keyup)
		    .each(function() { this.focus(); });

		 brush = svg.append("g")
		    .datum(function() { return {selected: false, previouslySelected: false}; })
		    .attr("class", "brush");


		 node = svg.selectAll(".node")
		    link = svg.selectAll(".link");

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