Simple-HTTP-Proxy
=================

A very simple and quick to setup HTTP proxy used to secure access to insecure devices.


## Background ##

During my tinkering with several "smart" home devices and IP cameras I've noticed many of them do not include SSL support, but do include basic HTTP authentication. This combination means that, in addition to all of the data being sent unencrypted, the authentication credentials are also sent in the clear.

I wanted a quick and easy way to expose these devices over the internet in a secure way with both the credentials and data being encrypted.

This is exactly the scenario in which a reverse proxy can be useful. Initially I was just going to setup proxy rewrite rules in IIS, but I ran into issues proxying mjpeg streams, among other issues.

Ultimately I decided it would be easier to throw together a quick node app that would be quick to setup and deploy without having to hassle with a full HTTP server.

## Setup ##

Clone the repo to a new, empty directory of your choice and then run `npm install` to download and install the required dependencies.

	$ git clone https://github.com/Justin-Credible/Simple-HTTP-Proxy.git
	$ cd Simple-HTTP-Proxy
	$ npm install

Next, edit the `config.json` file to setup the ports that will be used and the locations they will proxy to. You'll also want to setup your SSL certificate. See below for more details.

Then, start the proxy:

	$ node proxy.js

	=== Simple HTTP proxy =====================================
	21 Nov 03:14:21 - Starting up...
	Loading configuration from config.json...
	Configuration loaded!
	Initializing proxies...
	Setting up proxy on port 7777 (SSL) for destination: http://192.168.1.2
	Setting up proxy on port 8888 (SSL) for destination: http://192.168.1.3
	Setting up proxy on port 9999 (SSL) for destination: http://192.168.1.4
	Startup complete; waiting for requests...

In this example, a request to `https://localhost:7777/whatever.jpg` would be proxied to `http://192.168.1.2/whatever.jpg`.

## Configuration ##

All configuration is done via `config.json`. The following options are available.

### realm ###

The "realm" name which is displayed to the user by the browser in the authentication dialog.

	"realm": "Simple-HTTP-Proxy"

### userAccounts ###

This is a dictionary of user name strings to password strings. These are the credentials that all of the configured proxies will use to perform authentication.

	"userAccounts": {
		"user1": "password1",
		"user2": "password2"
	}

### proxies ###

This is an array of proxy configuration objects which define which ports to listen on and the destination to which to proxy incoming requests via `port` and `destination` respectively.

The `useSsl` flag will enable and disable SSL for the given port. This is useful for disabling encryption when debugging with an HTTP debugging proxy (like Fiddler). In non-debugging scenarios this should always be true (otherwise credentials will be sent in clear text).

Finally, if the optional `userName` and `password` properties are populated, they will be used to generate a [HTTP basic authentication](http://en.wikipedia.org/wiki/Basic_access_authentication) header for the destination request.

	"proxies": [
		{ "port": "7777", "useSsl": true, "destination": "http://192.168.1.2" },
		{ "port": "8888", "useSsl": true, "destination": "http://192.168.1.3" },
		{ "port": "9999", "useSsl": true, "destination": "http://192.168.1.4", "userName": "someUser", "password": "somePassword" }
	],

### certificatePath ###

The path to a SSL certificate to use for the incoming requests. Use by proxies that have `useSsl` set to true.

### certificatePassphrase ###

The passphrase for the SSL certificate, if the certificate has one set.

## License ##

Copyright © 2014 Justin Unterreiner.

Released under an MIT license; see [LICENSE](https://github.com/Justin-Credible/Simple-HTTP-Proxy/blob/master/LICENSE) for more information.