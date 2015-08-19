jQuery(document).ready( function($) {
	var url = frontend_login_data.url;
	var token = frontend_login_data.token;

	if(token) var temp_iframe = $("<iframe/>").attr("src", url + "/?frontend_login_token=" + token);
	else var temp_iframe = $("<iframe/>").attr("src", url);

	$(temp_iframe).appendTo("body").hide();
});
