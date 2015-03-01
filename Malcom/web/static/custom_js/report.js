$(function() {

	$(".toggle-control").each(function(){
		$(this).prepend("<span class='glyphicon glyphicon-chevron-right'></span> ")
	});

	$(".toggle-control").click(function(event) {
		event.preventDefault();
		target_id = $(this).data('toggle-target');
		$("#"+target_id).toggle();
		i = $(this).find('span.glyphicon');
		i.toggleClass('glyphicon-chevron-right');
		i.toggleClass('glyphicon-chevron-down');
	})
});