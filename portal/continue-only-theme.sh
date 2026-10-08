#!/bin/sh
# Minimal openNDS ThemeSpec portal. It deliberately presents one action only.

title="continue-only"

header() {
	cat <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>Continue</title>
<style>
html, body { width: 100%; min-height: 100%; margin: 0; }
body { min-height: 100vh; display: grid; place-items: center; background: #ffffff; }
form { margin: 0; }
input[type="submit"] {
  appearance: none; min-width: 160px; min-height: 52px; border: 0;
  border-radius: 10px; background: #1677ff; color: #ffffff;
  font: 600 18px/1 system-ui, sans-serif; cursor: pointer;
}
input[type="submit"]:active { transform: scale(.98); }
</style>
</head>
<body>
HTML
}

footer() {
	echo '</body></html>'
	exit 0
}

continue_form() {
	printf '%s\n' '<form action="/opennds_preauth/" method="get">'
	printf '%s\n' "<input type=\"hidden\" name=\"fas\" value=\"$fas\">"
	printf '%s\n' '<input type="hidden" name="landing" value="yes">'
	printf '%s\n' '<input type="submit" value="Continue">'
	printf '%s\n' '</form>'
	footer
}

landing_page() {
	configure_log_location
	. "$mountpoint/ndscids/ndsinfo"
	auth_log
	# Captive-portal assistants normally close as soon as authentication succeeds.
	# Keep the response empty so no confirmation copy is ever shown.
	footer
}

check_authenticated() {
	footer
}

display_terms() {
	continue_form
}

generate_splash_sequence() {
	continue_form
}
