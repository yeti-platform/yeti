$(function() {
	$("div.evil").click(function(event){
		event.preventDefault();
		id = $(this).data('id');
		$("#details-evil-"+id).toggle();
		i = $(this).find('i');
		i.toggleClass('icon-chevron-right');
		i.toggleClass('icon-chevron-down');
	});
});