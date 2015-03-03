$(function() {

	$('.field-selector').click(function(event){
		event.preventDefault();
		text = $(this).text();
		$("#selected-field").text(text);
		$("#field-selector").val(text.toLowerCase());
	});


});