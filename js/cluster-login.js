jQuery(document).ready( function($) {
	var url = cluster_login_data.url;
	var token = cluster_login_data.token;

	if(token) var temp_iframe = $("<iframe/>").attr("src", url + "/?cluster_login_token=" + token);
	else var temp_iframe = $("<iframe/>").attr("src", url);

	$(temp_iframe).appendTo("body").hide();
});
