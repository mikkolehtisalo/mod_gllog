![Coverity Scan Build Status](https://scan.coverity.com/projects/7722/badge.svg)

# mod_gllog

Mod_gllog interprets the authentication cookie used by Graylog2, and injects extra information to the request context for logging purposes. This can be used to enhance the access logs for the web interface with user information.

Extracted information:
* %{gl_username}n   - The name of the authenticated user
* %{gl_sessionid}n  - The session id
* %{gl_signaturevalid}n - Status for signature check

Results look like the following:

```
192.168.122.1 - - [24/Jan/2016:13:26:05 +0000] "GET /savedsearches HTTP/1.1" 200 261 "http://graylog.local:81/search?rangetype=relative&fields=message%2Csource&width=1920&relative=86400&q=" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0" "admin" "6cd192c1-f8e2-43c8-a061-b88e2-43c8-a061-b8" "valid"
192.168.122.1 - - [24/Jan/2016:13:26:05 +0000] "GET /a/system/fields HTTP/1.1" 200 695 "http://graylog.local:81/search?rangetype=relative&fields=message%2Csource&width=1920&relative=86400&q=" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0" "admin" "6cd192c1-f8e2-43c8-a061-b88e2-43c8-a061-b8" "valid"
192.168.122.1 - - [24/Jan/2016:13:26:06 +0000] "GET /a/dashboards/writable HTTP/1.1" 200 434 "http://graylog.local:81/search?rangetype=relative&fields=message%2Csource&width=1920&relative=86400&q=" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0" "admin" "6cd192c1-f8e2-43c8-a061-b88e2-43c8-a061-b8" "valid"
192.168.122.1 - - [24/Jan/2016:13:26:06 +0000] "GET /a/streams HTTP/1.1" 200 2873 "http://graylog.local:81/search?rangetype=relative&fields=message%2Csource&width=1920&relative=86400&q=" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0" "admin" "6cd192c1-f8e2-43c8-a061-b88e2-43c8-a061-b8" "valid"

```

# Installation and configuration

Compile and install the module:

```
apxs -i -c mod_gllog.c 
```

Add openssl and your module to the httpd.conf. If you used -a with apxs, you have to just add line for loading openssl, before loading the module.

```
LoadFile /usr/lib/x86_64-linux-gnu/libssl.so
LoadModule gllog_module /usr/lib/apache2/modules/mod_gllog.so
```

After that define a LogFormat that suits your needs.

```
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" \"%{gl_username}n\" \"%{gl_sessionid}n\" \"%{gl_signaturevalid}n\"" gl_combined
```

Enable the module and logging for the VirtualHost used for web interface.

```
<VirtualHost *:80>
		# Master switch for the module
		GlLog On
		# The application.secret for graylog-web, stolen from application.config
		GlLogKey "ae9a6138c6285163f1820e68cffda6191e0717e064917ee73642c819ca8b3e39f2e60d847f2a9f585ac53479f45365cb40cbaa7d1b102b8e5181704d695dedca"
		# Switch for checking validity of the signature
		GlLogSignature On
		
		# Use the LogFormat defined earlier
        CustomLog ${APACHE_LOG_DIR}/access.log gl_combined
</VirtualHost>

```
