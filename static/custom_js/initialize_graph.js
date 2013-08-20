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
		    .gravity(0.01)
		    .charge(-200)
		    .friction(0.8)
		    .linkDistance(70)
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

		    
}