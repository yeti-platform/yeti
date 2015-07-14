$(  function() {

	$(".switcher").click(function(e){
		e.preventDefault();
		yara_switch($(this).data('flowid'));
	});

	console.log('yara js loaded');
});

function yara_switch(fid) {
	$("#flows-tab").tab("show");
	window.location.hash = "#"+fid;
}