#!/usr/bin/nawk -f
# twitter.awk: twitter client for streaming api.
#
# 30110726: tested in Solaris nawk. split() doesn't work on null
#           terminator. back to using substr(s, i, 1). also delete arr
#           needs a loop: for (i in arr) delete arr[i]
# 20110726: Really getting somewhere. Started 3 days ago. Exported
#           'sha1sum', 'base64', and 'urlencode' functions to allow
#           use/test on files/stdin. sha1sum/base64 output mimics the
#           normal shell utilities :)
#
# I tried to organize my mind and split functions into groups
#  twitter_ - not much yet...
#     html_ - html specific encodings
#     json_ - json parser
#    oauth_ - OAuth, i made it all 1 function, =( still mostly generic
#     conv_ - numeric conversions
#      misc - just mkfifo
#     sha1_ - sha1 functions, operations with binary strings! *SLOW* heh
# quicksort - someone elses sort function
#
# all code my own except quicksort.. might just use a lil bubblesort,
#  it overkill for just the few oauth_ and post params sorting...
#
# license: SHOULD shoot me an email if you use it, MUST buy me a beer
#          if we meet. ;)
# july 2011. scott nicholas <neutronscott@scottn.us>

BEGIN {
	__configfile	= "twitter.conf"

	# I noticed 'for (i in arr)' segfaults Solaris nawk
	# if no array is passed, and length(arr) is illegal.
	# this is my workaround..
	__empty_arr[""] = "__empty_arr"

	## preliminary checks
	main()	# save global pollution!
}

function verbose_print(level, stuff)
{
	if (__verbose_level >= level)
		print stuff
}

## normal processing actions
# first the little helper/tester modes
__mode == "urlencode" { print html_urlencode($0);     next }
__mode == "entities"  { print html_entity_decode($0); next }
__mode == "sha1sum"   {
	print tolower(conv_bin2hex(sha1sum($0))) "  " FILENAME
	next
}
__mode == "base64"    {
	# shell utility wraps at 76 width.
	# and apparently ".{76}" doesn't work as a gsub pattern.
	p = ""
	for (i = 1; i <= 76; i++)
		p = p "."
	s = conv_base64(conv_hex2bin(conv_str2hex($0)));
	gsub(p, "&\n", s)
	print s
	next
}
__mode == "json"      {
	json_to_array($0, json)

	# more easy to read
	c = quicksort_indices(json, idx)
	for (i = 1; i <= c; i++)
		printf("[%s]=[%s]\n", idx[i], json[idx[i]])
	next
}

# rest is http connections. do this first.
#   can't believe i'm bothering with openssl s_client, need to check
#   length, it's possible (not with twitter json though afaik) to extend >1 line
__chunked && __chunked_zero { __chunked_zero = 0; next } # skip entirely
__chunked && !__chunked_len { __chunked_len = $0; next } # skip entirely...?
__chunked && __chunked_len  { __chunked_zero = 1 }# content on these line(s)
1 {	gsub("\r", "");
	verbose_print(3, "HTTP: " (__verbose_level>= 4&&length($0)>67)?$0 :\
	  substr($0, 1, 32) "..." substr($0, length($0) - 32))

}
__mode == "mentions" {
	json_to_array($0, json)

	# iterate fake-multi-demensional array, grab each mention separate
	for (i = 1; 1; i++) {
		if (json[i",text"] && json[i",user,screen_name"]) {
			printf("@%s: %s\n", json[i",user,screen_name"], \
			                    html_entity_decode(json[i",text"]))
		} else {
			break
		}
	}
	next
}

# should be friends list. bah!
NR == 1 {
	print "*** Welcome!"
	next
}

# the meat.. normal streaming json stuffs
1 {
	# print the keep-alive dots ...
	if (length($0) < 1) { printf("."); next }
	else { print "" }

	json_to_array($0, json)

	if (json["text"])
	{
		text = html_entity_decode(json["text"])
		printf("@%s: %s\n", json["user,screen_name"], text);
		if (tolower(text) ~ /^@neutronbot .*(hi|hello)/) {
			reply = "@" json["user,screen_name"] " why, hello to you too!"
			print ">> " reply
			twitter_update_status(oauth, reply)
		} else if (json["user,screen_name"] != "neutronscott")
			next # privledged commands follow
		else if (tolower(text) ~ /^@neutronbot say /) {
			reply = substr(text, 17)
			print ">> " reply
			twitter_update_status(oauth, reply)
		}
	}
}

## main program functions
function main(	header, ret)
{
	# FIXME: we need this early for now. sucks if using a mini-utility ...
	config_read()

	if (ARGV[1] ~ /^(stream|live)$/) {
		oauth["uri"] = "https://userstream.twitter.com/2/user.json"
		__mode = "live"
	} else if (ARGV[1] == "mentions") {
		print "OK we'll test that out..."
		__mode = "mentions"
		oauth["uri"] = "https://api.twitter.com/1/statuses/mentions.json"
	} else if (ARGV[1] == "whoami") {
		twitter_verify_user(oauth)
		exit
	} else if (ARGV[1] == "newuser") {
		twitter_new_user(oauth)
		exit
	# some sub-functions to test or use...
	} else if (ARGV[1] == "json") {
		__mode = "json"
	} else if (ARGV[1] == "urlencode") {
		__mode = "urlencode"
	} else if (ARGV[1] == "entities") {
		__mode = "entities"
	} else if (ARGV[1] == "sha1sum") {
		__mode = "sha1sum"
	} else if (ARGV[1] == "base64") {
		__mode = "base64"
	} else {
		show_usage()
		exit
	}

	ARGC--
	delete ARGV[1]	# it was a command, not a file for awk to open..

	# the real program, eh
	if ((__mode == "live") || (__mode == "mentions")) {
		check_required_cmds()

		# not absolutely needed. but use awk's normal file processing
		#  this way instead of a getline loop in BEGIN{} ... meh
		if (mkfifo(ret) > 0)
		{
			print "Error creating fifo ..."
			exit
		}
		http["fifo"] = ret[0]

		print "Starting feed..."
		header = oauth_header(oauth, __empty_arr)
		http["cmd"] = http_open(oauth, header, __empty_arr, \
		              http["fifo"])
		if (http["cmd"] ~ /^ERROR/) {
			print http["cmd"]
			exit
		}
		print "Starting processing..."
		ARGV[1] = http["fifo"]
		ARGC = 2
	}
}

function show_usage()
{
	print	"Usage: twitter.awk <mode>\n" \
		"\n" \
		"Mode MUST be ONE of the following:\n" \
		"stream|live   - streaming api\n" \
		"newuser       - get tokens for user\n" \
		"whoami        - show information about user who owns token\n" \
		"mentions      - get latest 20 mentions\n" \
		"\n" \
		"Operations on stdin or optional file:\n" \
		"json          - parse and dump a json file\n" \
		"urlencode     - urlencodes stdin.\n" \
		"entities      - test html_entity_decode()\n" \
		"sha1sum       - calculate sha-1 hash\n" \
		"base64        - base64 encode\n"
}

function config_read()
{
	while ((getline < __configfile) > 0)
	{
		if ($0 ~ /^#/)		# skip comment lines
			continue
		if ($1 == "consumer_key")
			oauth["consumer_key"] = $2
		else if ($1 == "consumer_secret")
			oauth["consumer_secret"] = $2
		else if ($1 == "token")
			oauth["token"] = $2
		else if ($1 == "token_secret")
			oauth["token_secret"] = $2
		else if ($1 == "verbose") {	# "verbose" or "verbose level"?
			if (NF > 1)
				__verbose_level = $NF
			else
				__verbose_level = 1
		} else if ($1 == "html") {
			__html_entity[tolower($2)] = sprintf("%04x", $3)
		} else if ($1 == "use") {
			__conf["cmd", "http"] = $2
		}
	}
	close(__configfile)
}

function config_replace_token(token, token_secret,
	buffer, i, n, c)
{
	while ((getline < __configfile) > 0)
		buf[++i] = $0
	close(__configfile)
	n = i;
	for (i = 1; i <= n; i++)
	{
		if (tolower(buf[i]) ~ /^token/) {
			print "#" buf[i] > __configfile
			if (++c == 2) {		# keep new under old.
				print "token\t\t" token > __configfile
				print "token_secret\t" token_secret > __configfile
			}
		} else
			print buf[i] > __configfile
	}
	# in case there was none..
	if (c < 2) {
		print "token\t\t" token > __configfile
		print "token_secret\t" token_secret > __configfile
	}
	close(__configfile)
}

###############################################################################
###############################################################################
###############################################################################
function twitter_update_status(credentials, status,
	i, oauth, params, header, http)
{
	for (i in credentials) oauth[i] = credentials[i]
	oauth["method"] = "POST"
	oauth["uri"] = "https://api.twitter.com/1/statuses/update.json"

	params["status"] = status

	header = oauth_header(oauth, params)
	http = http_open(oauth, header, params)
	if (http ~ /^ERROR/) {
		print "update_status: " http
		return
	}
	while ((http | getline) > 0)
	{
#		print "http: " $0
	}
	close(http)
}

function twitter_new_user(credentials,
	i, oauth, header, params, http, token, content, str, a, b,
	pin, ok)
{
	## only need our info. we're getting client infos..
	oauth["consumer_key"]    = credentials["consumer_key"]
	oauth["consumer_secret"] = credentials["consumer_secret"]

	## first request_token
	oauth["method"] = "POST"
	oauth["uri"] = "https://api.twitter.com/oauth/request_token"

	params["oauth_callback"] = "oob"

	header = oauth_header(oauth, params)
	http = http_open(oauth, header, params)
	if (http ~ /^ERROR/) {
		print http
		return
	}
	while ((http | getline) > 0)
	{
		gsub("\r", "")
		verbose_print(1, $0)
		token_str = token_str $0
	}
	close(http)

	n = split(token_str, a, "(&|=)")
	for (i = 1; i <= n; i += 2)
		token[a[i]] = a[i+1]

	printf("Have user visit: [https://api.twitter.com/oauth/authorize?oauth_token=%s]\n", token["oauth_token"])

	while (1) {
		pin = prompt("PIN:")
		ok = prompt("PIN [" pin "] is correct?")
		if (ok ~ /[Yy]/) break
	}

	for (i in params)
		delete params[i]
	params["oauth_verifier"] = "" pin
	oauth["token"]           = token["oauth_token"]
	oauth["token_secret"]    = token["oauth_token_secret"]

	twitter_auth_user(oauth, params)
}

function prompt(p,
	res)
{
	printf("%s ", p)
	getline res < "-"
	return res
}

# params["oauth_verifier"] = PIN
function twitter_auth_user(credentials, params,
	i, oauth, header, http, token_str, token, content, str, a, n)
{
	oauth["consumer_key"] = credentials["consumer_key"]
	oauth["consumer_secret"] = credentials["consumer_secret"]
	oauth["token"] = credentials["token"]
	oauth["token_secret"] = credentials["token_secret"]

	## then access_token
	oauth["method"] = "POST"
	oauth["uri"] = "https://api.twitter.com/oauth/access_token"

	header = oauth_header(oauth, params)
	http = http_open(oauth, header, params)
	if (http ~ /^ERROR/) {
		print http
		return
	}
	while ((http | getline) > 0)
	{
		gsub("\r", "")
		token_str = token_str $0
	}
	close(http)

	n = split(token_str, a, "(&|=)")
	for (i = 1; i <= n; i += 2)
	{
		token[a[i]] = a[i+1]
		verbose_print(2, "[" a[i] "]=[" a[i+1] "]")
	}
	config_replace_token(token["oauth_token"], token["oauth_token_secret"])
}

function twitter_verify_user(credentials,
	i, oauth, header, http, content, json)
{
	for (i in credentials) oauth[i] = credentials[i]
	oauth["method"] = "GET"
	oauth["uri"] = "https://api.twitter.com/1/account/verify_credentials.json"

	header = oauth_header(oauth, __empty_arr)
	http = http_open(oauth, header, __empty_arr)
	if (http ~ /^ERROR/)
	{
		print http
		return
	}
	while ((http | getline) > 0)
	{
		json_to_array($0, json)
		printf("Screen name: %s  [id:%d]\nDescription: %s\n\n", \
		       json["screen_name"], json["id"], json["description"])
		printf("Statuses: %d\n", json["statuses_count"])
		printf("Following: %d Followers: %d\n", \
		       json["friends_count"], json["followers_count"])
	}
	close(http)
}

###############################################################################
###############################################################################
###############################################################################
function html_entity_decode(str,
	i, start, result, c, hex)
{
	for (i = start = 1; i = match(substr(str, start), "&[^;]+;"); )
	{
		# add stuff that is previous-to-match
		result = result substr(str, start, i - 1)
		start += i - 1
		entity = tolower(substr(str, start + 1, RLENGTH - 2))

		# easy speezy if it's already a numeric, no lookup-table! :D
		if (entity ~ /^#/) {
			if (substr(entity, 2, 1) == "x")	#hex
			{
				hex = substr(entity, 3)
				while (length(hex) < 4)
					hex = "0" hex
				c = conv_unicode_to_utf8(hex)
			} else {
				c = conv_unicode_to_utf8( \
					sprintf("%04x", 0+substr(entity, 2)))
			}
		# hard-code the basic and essential ones [XML 1.0]
		} else if (entity == "quot")	c = "\""
		else if (entity == "amp")	c = "&"
		else if (entity == "apos")	c = "'"
		else if (entity == "lt")	c = "<"
		else if (entity == "gt")	c = ">"
		else if (entity == "nbsp")	c = " "
		else if (entity in __html_entity) {
			c = conv_unicode_to_utf8(__html_entity[entity])
		} else {
			# put it back together. meh.
			c = "&" entity ";"
		}

		result = result c
		start += RLENGTH
	}
	if (result) {
		# add stuff after match
		result = result substr(str, start)
		return result
	}
	return str
}

function html_urlencode(str,
	n, a, i, c, h, encoded)
{
	for (i = 1; i <= length(str); i++) {
		c = substr(str, i, 1)
		# as per oauth1.0 specs
		if (c ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-]/) {
			encoded = encoded c
		} else {
			h = conv_str2hex(c)
			gsub("..", "%&", h)
			encoded = encoded h
		}
	}
	return encoded
}

function http_get_header(cmd)
{
	gsub("\r", "")
	verbose_print(2, "HTTP-Header[" length($0) "]: " $0)
	if ($0 ~ /^HTTP/) {
		verbose_print(1, $0)
		if ($2 != "200") {
			close(cmd)
			return "ERROR " $0
		}
	}
	if (length($0) == 0) return 0
	return 1
}

function http_open(credentials, header, params, fifo,
	params_str, cmd, i, host, path, h_cmd)
{
	if (params[""] != "__empty_arr") {	# empty/optional workaround
		for (i in params)
			params_str = (params_str ? params_str "&" : "") \
				html_urlencode(i) "=" html_urlencode(params[i])
	}

	if (__conf["cmd", "http"] == "openssl")
	{
		# oh this sucks. basically gotta make a simple http client :P
		i = match(credentials["uri"], "://")
		host = substr(credentials["uri"], i + 3)
		i = index(host, "/")
		path = substr(host, i)
		host = substr(host, 1, i - 1)

		if (params_str && (credentials["method"] == "GET"))
			path = path "?" params_str

		c_header =	"GET " path " HTTP/1.1\n" \
				"User-Agent: twitter.awk/1.0\n" \
				"Host: " host "\n" \
				header "\n\n" \
				"__EOF__\n"

		cmd =	"openssl s_client -quiet -connect " host ":443 " \
			(fifo?(">" fifo):"") " <<__EOF__\n" c_header

		# couldn't for the live of me just read the headers off the fifo
		# before awk opens it as an ARGV file without it gobbling up
		# too much. must be buffer size. this should read char-by-char
		# to get a LINE and THAT IS IT and leave my CONTENT ALONE!
		if (fifo) {
			print "" | cmd	# kick it off
			h_cmd = "while read A && [ \"${#A}\" -gt 2 ]; do echo \"${A}\"; done < " fifo
			while ((h_cmd | getline) > 0 && http_get_header(cmd)) {
				if ($0 ~ /chunked/) __chunked = 1
			}
			verbose_print(3, "close header helper.")
			close(h_cmd)	# awk reopens as ARGV[1] for normal procsesing

		} else {
			# i'll have to pretty this up later.
			# same code 3 times? ick
			while ((cmd | getline) > 0 && http_get_header(cmd)) {
				if ($0 ~ /chunked/) __chunked = 1
			}
		}
	} else {
		cmd =	"exec curl -D - -s -N '" credentials["uri"] \
			"' -H '" header "'"
		if (params_str)
			cmd = cmd " -d '" params_str "'"
		if (fifo)
			cmd = cmd " -o " fifo
		# gobber header, always on stdout
		while ((cmd | getline) > 0  && http_get_header(cmd)) {
			# null
		}
	}

	verbose_print(1, "HTTP command: [" cmd "]")
	return cmd
}

###############################################################################
###############################################################################
###############################################################################
function json_add_element(arr, val, level, ordered, key,
	i, k)
{
	# empty set
	if (!length(val)) return
	k = ""
	for (i = 1; i <= level; i++)
		k = k (ordered[i] ? ordered[i] : key[i]) (i < level ? "," : "")
	arr[k] = val
}

function json_to_array(json_str, arr,
	i, a, n, backslash, quote, code, val, key, level, ordered)
{
	for (i in arr)
		delete arr[i]
	level = 0;
	for (i = 1; i <= length(json_str); ++i)
	{
		c = substr(json_str, i, 1)
		if (backslash) {
			backslash = 0;
			if (c == "u") {
				code = toupper(substr(json_str, i + 1, 4))
				i += 4; #take em off stack, kinda...
				val = val conv_unicode_to_utf8(code)
			} else {
				val = val c
			}
		} else if (c == "\\") {
			backslash = 1;
			continue;
		} else if (c == "\"") {
			quote = !quote
		} else if (quote) {
			if (c != "\\" || p == "\\") val = val c
		} else if (c == ":") {
			key[level] = val
			val = ""
		} else if (c == "[") {
			level++
			ordered[level] = 1
		} else if (c == "{") {
			level++
		} else if (c ~ /[]}]/) {
			json_add_element(arr, val, level, ordered, key)
			val = ""
			delete ordered[level]
			level--
		}
		else if (c == ",") {
			if (p !~ /[]}]/) {
				json_add_element(arr, val, level, ordered, key)
				val = ""
			}
			if (ordered[level]) ordered[level]++
		} else {
			val = val c
		}
		p = c #previous (uh, need better states)
	}
}

##########################################################################
##########################################################################
##########################################################################
function oauth_header(credentials, params,
	bs, cmd, str, i, c, params_str, base_string, key,
	signature, header, method)
{
	## first we need the base string

	# populate parameters used to calculate base string
	bs["oauth_version"]		= "1.0"
	bs["oauth_consumer_key"]	= credentials["consumer_key"]
	bs["oauth_signature_method"]	= "HMAC-SHA1"

	if (credentials["token"])
		bs["oauth_token"]	= credentials["token"]
	if (credentials["timestamp"] == "") {
		cmd = "date +%s"
		cmd | getline str
		close(cmd)
		bs["oauth_timestamp"]	= "" str
	} else {
		bs["oauth_timestamp"]	= credentials["timestamp"]
	}
	if (credentials["nonce"] == "") {
		cmd = "date +%s.%N"
		cmd | getline str
		str = tolower(conv_bin2hex(sha1sum(str)))
		bs["oauth_nonce"]	= str
		close(cmd)
	} else {
		bs["oauth_nonce"]	= credentials["nonce"]
	}
	if (credentials["method"] == "")
		method = "GET"
	else
		method = credentials["method"]

	# merge with request parameters
	# empty/optional array workaround for nawk
	if (params[""] != "__empty_arr")
		for (i in params)
			bs[i] = params[i]

	# oops.
	for (i in bs)
		bs[i] = html_urlencode(bs[i])

	# must be normalized so our calculations match servers
	c = quicksort_indices(bs, idx)
	for (i = 1; i <= c; i++)
		params_str = params_str idx[i] "=" bs[idx[i]] \
		             ((i != c) ? "&" : "")

	# put it all together
	base_string = method "&" html_urlencode(credentials["uri"]) "&" \
	              html_urlencode(params_str)

	## then we need a signature
	key = html_urlencode(credentials["consumer_secret"]) "&" \
	      html_urlencode(credentials["token_secret"])

	signature = conv_base64(sha1_hmac( \
		    conv_hex2bin(conv_str2hex(key)), \
		    conv_hex2bin(conv_str2hex(base_string)) ))

	verbose_print(1, "sha1_hmac('" key "',\n\t'" base_string "') = " \
		signature)

	## concat a header out of all this
	header = "Authorization: OAuth "
	header = header "oauth_consumer_key=\"" html_urlencode(bs["oauth_consumer_key"]) "\", "
	if (credentials["token"])
		header = header "oauth_token=\"" \
		         html_urlencode(bs["oauth_token"]) "\", "
	header = header "oauth_signature_method=\"" html_urlencode(bs["oauth_signature_method"]) "\", "
	header = header "oauth_signature=\"" html_urlencode(signature) "\", "
	header = header "oauth_timestamp=\"" html_urlencode(bs["oauth_timestamp"]) "\", "
	header = header "oauth_nonce=\"" html_urlencode(bs["oauth_nonce"]) "\", "
	header = header "oauth_version=\"" html_urlencode(bs["oauth_version"]) "\""

	verbose_print(1, header)
	return header
}

##########################################################################
##########################################################################
##########################################################################
function conv_init(	i, j, c, h, a)
{
	__conv_init = 1
	split("1 2 3 4 5 6 7 8 9 A B C D E F", __hextab, " ")
	split("0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111", __bintab, " ")
	__hextab[0] = 0
	__bintab[0] = "0000"
	for (i = 1; i <= 255; ++i)
		__chr2hex[sprintf("%c", i)""] = sprintf("%02X", i)
	for (i = 0; i < 16; i++) {
		__hex2bin[__hextab[i]] = __bintab[i]
		__bin2dec[__bintab[i]] = i
		__bin2hex[__bintab[i]] = __hextab[i]
#		__hex2dec[__hextab[i]] = i
	}
	if (length(conv_unicode_to_utf8("FEFF")) == 1) {
		print	"********************************************************\n" \
			"* WARNING: Please set LANG=C, otherwise start-up time  *\n" \
			"* suffers by requiring a larger ordinal table of WCHAR *\n" \
			"********************************************************\n"
		for (i = 1; i <= 255; ++i) {
			for (j = 0; j <= 255; ++j) {
				h = sprintf("%02X%02X", i, j)
				c = conv_unicode_to_utf8(h, a)
				__chr2hex[c] = a[0]
			}
			if (i % 25 == 5)
				printf("%5.2f%% complete...\n", 100*i/255)
		}
	}
}

#input is binary string as well...
function conv_base64(t,
	i, b64, b, res)
{
	b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	# pad input. takes 6 bits to make 64-positions.
	while (length(t) % 6)
		t = t "0"

	for (i = 1; i < length(t); i += 6) {
		d  = 16 * __bin2dec["00" substr(t, i, 2)] + \
		     __bin2dec[substr(t, i+2, 4)]
		b = substr(b64, d + 1, 1)
		res = res b
	}

	# pad out. end with '='. every 3 char transforms to 4, so output
	# must be multiple of 4.
	while (length(res) % 4)
		res = res "="

	return res
}

function conv_hex2bin(hex,
	i, bin)
{
	if (!__conv_init) conv_init()
	for (i = 1; i <= length(hex); i++)
		bin = bin __hex2bin[toupper(substr(hex, i, 1))]
	return bin
}

function conv_str2hex(str,
	n, a, i, hex)
{
	if (!__conv_init) conv_init()
	for (i = 1; i <= length(str); i++)
		hex = hex __chr2hex[substr(str, i, 1)]
	return hex
}

function conv_bin2chr(bin,
	i, chr)
{
	if (!__conv_init) conv_init()
	for (i = 1; i <= length(bin); i += 8)
	{
		chr = chr sprintf("%c", \
			16 * __bin2dec[substr(bin, i,   4)] + \
			     __bin2dec[substr(bin, i+4, 4)])
	}
	return chr
}

function conv_bin2hex(bin,
	i, hex)
{
	if (!__conv_init) conv_init()
	for (i = 1; i <= length(bin); i += 4)
		hex = hex __bin2hex[substr(bin, i, 4)]
	return hex
}

# to build WCHAR we need to know the character represented in hex...
# so just pass an arr as 2nd argument and it'll be copied to arr[0]
# if only awk could convert a char into an int... :(
function conv_unicode_to_utf8(hex, arr,
	bin, blen, utf8)
{
	if (length(hex) != 4) return ""	# i dunno

	# hex2bin
	bin = conv_hex2bin(hex)
	blen = 17 - index(bin, "1")

	# then add UTF-8 prefixes. we have 2 bytes right now.
	if (blen > 11)
		utf8 = "1110" substr(bin, 1, 4) "10" substr(bin, 5, 6) \
			"10" substr(bin, 11, 6)
	else if (blen > 7)
		utf8 = "110" substr(bin, 6, 5) "10" substr(bin, 11, 6)
	else
		utf8 = substr(bin, 9)

	# pass back in array too
	arr[0] = conv_bin2hex(utf8)

	# then back to ... characters? :O
	return conv_bin2chr(utf8)
}

##########################################################################
##########################################################################
##########################################################################
function check_required_cmds(	cmds, i, cmd, line, some_missing)
{
	## we need all of these...
	cmds["date"] = cmds["which"] = 0
	if (__conf["cmd", "http"] == "openssl") {
		cmds["openssl"] = 0
		cmds["cat"] = 0
	} else {
		cmds["curl"] = 0
	}

	for (i in cmds) cmd = cmd " " i
	cmd = "which" cmd " 2>/dev/null"
	while ((cmd | getline) > 0)
	{
		basename = $0
		gsub(".*/", "", basename)
		if (basename in cmds)
			cmds[basename] = $0
	}
	close(cmd)
	for (i in cmds)
	{
		if (cmds[i] == 0) {
			if (!some_missing) {
				some_missing = 1
				print "***************************************************\n" \
				      "* ERROR: Missing the following required programs: *"
			}
			printf("* %-47s *\n", i)
		} else
			verbose_print(3, "Command [" i "] available at [" \
				cmds[i] "]")
	}
	if (some_missing) {
		print "***************************************************\n"
		exit
	}
}

# use arr to pass by reference ...
function mkfifo(arr, template,
	cmd, exitnow)
{
	if (template == "")
		template = "twitter.fifo"
	devnull = " >/dev/null 2>&1"
	cmd = "unlink " template devnull "; mkfifo -m 600 " template devnull \
		"; printf '%d\n%s\n' $? " template
	cmd | getline exitcode
	cmd | getline arr[0]
	close(cmd)
	return exitcode
}

# if mine breaks, or user wants speeeed ;\
function base64_sha1_hmac(key, text)
{
	cmd = "printf '%s' '" text "' | openssl dgst -sha1 -binary -hmac '" key "' | base64"
	cmd | getline hmac
	close(cmd)

	return hmac
}
##########################################################################
##########################################################################
##########################################################################
function test_hmac(	test, text, key, out, hmac, i) {
	test[++i] = "Sample message for keylen=blocklen"
	text[i]   = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"
	key[i]    = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
	out[i]    = "5FD596EE78D5553C8FF4E72D266DFD192366DA29"

	test[++i] = "Sample message for keylen<blocklen"
	text[i]   = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"
	key[i]    = "000102030405060708090A0B0C0D0E0F10111213"
	out[i]    = "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807"

	test[++i] = "Sample message for keylen=blocklen  [sic, keylen>blocklen]"
	text[i]   = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"
	key[i]    = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263"
	out[i]    = "2D51B2F7750E410584662E38F133435F4C4FD42A"

	test[++i] = "Sample message for keylen<blocklen, with truncated tag"
	text[i]   = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E2C2077697468207472756E636174656420746167"
	key[i]    = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
	out[i]    = "FE3529565CD8E28C5FA79EAC"

	for (i in test)
	{
		hmac = conv_bin2hex( \
		                    sha1_hmac(conv_hex2bin(key[i]), \
		                              conv_hex2bin(text[i])))
		printf("Test: %s\nsha1_hmac: %s\nExpected : %s\n\n", \
		       test[i], hmac, out[i])
	}
}

function sha1_xor(a, b,
	c, d, n, i, res)
{
	n = length(a)
	for (i = 1; i <= n; i++)
	{
		c = substr(a, i, 1)
		d = substr(b, i, 1)
		if ((c != d) && (c == "1" || d == "1"))
			res = res "1"
		else
			res = res "0"
	}
	return res
}

function sha1_and(a, b,
	c, d, n, i, res)
{
	n = length(a)
	for (i = 1; i <= n; i++)
	{
		c = substr(a, i, 1)
		d = substr(b, i, 1)
		if ((c == d) && (c == "1"))
			res = res "1"
		else
			res = res "0"
	}
	return res
}

function sha1_or(a, b,
	c, d, n, i, res)
{
	n = length(a)
	for (i = 1; i <= n; i++)
	{
		c = substr(a, i, 1)
		d = substr(b, i, 1)
		if ((c == "1") || (d == "1"))
			res = res "1"
		else
			res = res "0"
	}
	return res
}

function sha1_add(a, b,
	c, d, n, i, carry, sum, res)
{
	n = length(a)
	for (i = n; i > 0; i--)
	{
		c = substr(a, i, 1)
		d = substr(b, i, 1)
		sum = carry + c + d
		if (sum == 2) { carry = 1; sum = 0 }
		else if (sum == 3) { carry = 1; sum = 1 }
		else { carry = 0; }
		res = sum res
	}
	return res
}

function sha1_not(a,
	n, i, res)
{
	n = length(a)
	for (i = 1; i <= n; i++)
	{
		if (substr(a, i, 1) == "0")
			res = res "1"
		else
			res = res "0"
	}
	return res
}

# input are in binary strings. only for SHA-1..
function sha1_hmac(K, t,
	B, bin)
{
	B = 512	#block length of hash. SHA-1 is 512

	# make K same length as text.
	if (length(K) > B)
		K = sha1sum(K)
	while (length(K) < B)
		K = K "0"

	# always same length, just check for existance
	if (!__sha1_ipad)
		while (length(__sha1_ipad) < B)
			__sha1_ipad = __sha1_ipad "00110110"	# 0x36
	if (!__sha1_opad)
		while (length(__sha1_opad) < B)
			__sha1_opad = __sha1_opad "01011100"	# 0x5C

	return sha1sum(sha1_xor(K, __sha1_opad) \
		sha1sum(sha1_xor(K, __sha1_ipad) t))
}

# input is binary, or string I guess...
function sha1sum(str,
	h0, h1, h2, h3, h4, a, b, c, d, e,
	i, j, len, pad, padded_length, chunk, w)
{
	h0 = "01100111010001010010001100000001"
	h1 = "11101111110011011010101110001001"
	h2 = "10011000101110101101110011111110"
	h3 = "00010000001100100101010001110110"
	h4 = "11000011110100101110000111110000"

	if (str ~ /[^01]/)
		bin = conv_hex2bin(conv_str2hex(str))
	else
		bin = str

	# append '1', pad to 512 block size (minus 64 for length)
	len = length(bin)
	bin = bin "1"
	# this has to be slow. i suck at math.
	while (length(bin) % 512 != 448)
		bin = bin "0"

	# convert length to 64-bit word and append it.
	len = conv_hex2bin(sprintf("%X", len))
	pad = 64 - length(len)
	for (i = 1; i <= pad; i++)
		len = "0" len
	bin = bin len

	padded_length = length(bin)
	for (i = 1; i <= padded_length; i += 512)
	{
		# process each 512-bit chunk separate
		chunk = substr(bin, i, 512)

		# break into 16 32-bit words
		for (j = 0; j < 16; j++)
			w[j] = substr(chunk, 32 * j + 1, 32)

		# extend into 80 words
		for (j = 16; j <= 79; j++) {
			# w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
			w[j] = sha1_xor(sha1_xor(sha1_xor(w[j-3], w[j-8]), w[j-14]), w[j-16])
			# << 1
			w[j] = substr(w[j], 2) substr(w[j], 1, 1)
		}

		# init hash value for this chunk
		a = h0; b = h1; c = h2; d = h3; e = h4

		for (j = 0; j <= 79; j++) {
			if (j <= 19) {
				# f = (b & c) | (!b & d)
				f = sha1_or(sha1_and(b,c),sha1_and(sha1_not(b), d))
				k = "01011010100000100111100110011001"
			} else if (j <= 39) {
				# f = b ^ c ^ d
				f = sha1_xor(sha1_xor(b,c),d)
				k = "01101110110110011110101110100001"
			} else if (j <= 59) {
				# f = (b & c) | (b & d) | (c & d)
				f = sha1_or(sha1_and(b,c),sha1_or(sha1_and(b,d),sha1_and(c,d)))
				k = "10001111000110111011110011011100"
			} else {
				# f = b ^ c ^ d
				f = sha1_xor(sha1_xor(b,c),d)
				k = "11001010011000101100000111010110"
			}

			# temp = (a<<5) + f + e + k + w[j]
			temp = substr(a, 6) substr(a, 1, 5)
			temp = sha1_add(sha1_add(temp,f),sha1_add(sha1_add(e,k),w[j]))
			e = d
			d = c
			c = substr(b, 31) substr(b, 1, 30)	# b << 30
			b = a
			a = temp

			if (__debug)
			printf("t=%2d: %8s %8s %8s %8s %8s\n", j,\
				conv_bin2hex(a),conv_bin2hex(b),\
				conv_bin2hex(c),conv_bin2hex(d),\
				conv_bin2hex(e))
		}
		h0 = sha1_add(h0, a)
		h1 = sha1_add(h1, b)
		h2 = sha1_add(h2, c)
		h3 = sha1_add(h3, d)
		h4 = sha1_add(h4, e)
	}
	return h0 h1 h2 h3 h4
}

##########################################################################
##########################################################################
##########################################################################
# quicksort.awk from RunAWK
# Written by Aleksey Cheusov <vle@gmx.net>, public domain
function __quicksort (array, index_remap, start, end,
       MedIdx,Med,v,i,storeIdx)
{
	if ((end - start) <= 0)
		return

	MedIdx = int((start+end)/2)
	Med = array [index_remap [MedIdx]]

	v = index_remap [end]
	index_remap [end] = index_remap [MedIdx]
	index_remap [MedIdx] = v

	storeIdx = start
	for (i=start; i < end; ++i){
		if (array [index_remap [i]] < Med){
			v = index_remap [i]
			index_remap [i] = index_remap [storeIdx]
			index_remap [storeIdx] = v

			++storeIdx
		}
	}

	v = index_remap [storeIdx]
	index_remap [storeIdx] = index_remap [end]
	index_remap [end] = v

	__quicksort(array, index_remap, start, storeIdx-1)
	__quicksort(array, index_remap, storeIdx+1, end)
}

function quicksort (array, index_remap, start, end,             i)
{
	for (i=start; i <= end; ++i)
		index_remap [i] = i

	__quicksort(array, index_remap, start, end)
}

function quicksort_values (hash, remap_idx,
   array, remap, i, j, cnt)
{
	cnt = 0
	for (i in hash) {
		++cnt
		array [cnt] = hash [i]
		remap [cnt] = i
	}

	quicksort(array, remap_idx, 1, cnt)

	for (i=1; i <= cnt; ++i) {
		remap_idx [i] = remap [remap_idx [i]]
	}

	return cnt
}

function quicksort_indices (hash, remap_idx,
   array, i, cnt)
{
	cnt = 0
	for (i in hash) {
		++cnt
		array [cnt] = i
	}

	quicksort(array, remap_idx, 1, cnt)

	for (i=1; i <= cnt; ++i) {
		remap_idx [i] = array [remap_idx [i]]
	}

	return cnt
}
