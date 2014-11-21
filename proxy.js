
/*jshint node: true*/

/** Imports **************************************************************************/

var
	fs = require("fs"),
	util = require("util"),
	http = require("http"),
	https = require("https"),
	httpProxy = require("http-proxy"),
	auth = require("basic-auth"),
	stripJsonComments = require("strip-json-comments");

/** Application Configuration and Globals ********************************************/

// Will be loaded via config.json during application startup.
var config;

/** Helper Methods *******************************************************************/

// Used to generate an authorization HTTP header.
var getBasicAuthorizationHeader = function (userName, password) {
	var encodedCredentials;

	if (userName == null) {
		userName = "";
	}

	if (password == null) {
		password = "";
	}

	// http://en.wikipedia.org/wiki/Basic_access_authentication
	encodedCredentials = new Buffer(userName + ":" + password).toString("base64");

	return "Basic " + encodedCredentials;
};

// Used to validate user name and password against the userAccounts list.
var validateCredentials = function (userName, password) {
	// Currently the only validation is to lookup the user by name in the
	// dictionary and see if the password is a match.
	return config.userAccounts[userName] === password;
};

/** HTTP Request Handler *************************************************************/

// The handler that will execute for the incoming requests.
var requestHandler = function (proxyServer, proxyInfo, request, response) {
	var credentials;

	// Obtain and decode the username/password from the Authorization header.
	credentials = auth(request);

	// Attempt to validate the crendetials; if they are not valid OR are not present
	// then respond with a 401 which will cause the browser to prompt for credentials.
	if (!credentials || !validateCredentials(credentials.name, credentials.pass)) {

		// Log the authentication request failure.
		util.log(util.format("%s -> %s %s %s -> 401 UNAUTHORIZED (credentials: %s)",
			request.headers.host,
			proxyInfo.destination,
			request.method,
			request.url,
			credentials ? credentials.name + ":" + credentials.pass : "null"));

		response.writeHead(401, {
			"WWW-Authenticate": util.format("Basic realm='%s'", config.realm)
		});

		response.end();

		return;
	}

	// If the credentials were valid, then continue on.
	util.log(util.format("%s -> %s %s %s",
		request.headers.host,
		proxyInfo.destination,
		request.method,
		request.url));

	// If this proxy has a user name and/or password provided, then we'll include it
	// otherwise we'll null out the header so these crendentials aren't sent along
	// in the request to the destination.
	if (proxyInfo.userName || proxyInfo.password) {
		request.headers.Authorization = getBasicAuthorizationHeader(proxyInfo.userName, proxyInfo.password);
	}
	else {
		delete request.headers.Authorization;
	}

	// Delegate to the proxy server object to proxy the request.
	proxyServer.web(request, response, { target: proxyInfo.destination });
};

/** Application Logic ****************************************************************/

(function () {
	var configJson, proxyServer;

	console.log("=== Simple HTTP proxy =====================================");

	util.log("Starting up...");
	console.log("Loading configuration from config.json...");

	// Read in the configuration JSON file.
	configJson = fs.readFileSync("config.json", "UTF-8");

	// We have to strip out the comments because the JSON spec doesn't allow them.
	configJson = stripJsonComments(configJson);

	// Parse the configuration.
	config = JSON.parse(configJson);

	console.log("Configuration loaded!");
	console.log("Initializing proxies...");

	// Setup a shared proxy server instance; this will perform the heavy lifting.
	proxyServer = httpProxy.createProxyServer({});

	// For each of the proxy entries, setup a proxy server.
	config.proxies.forEach(function (proxyInfo) {
		var httpsServerOptions = {}, handler;

		console.log(util.format("Setting up proxy on port %s (%s) for destination: %s",
			proxyInfo.port,
			proxyInfo.useSsl ? "SSL" : "non-SSL",
			proxyInfo.destination));

		// Bind the request handler function so we can include extra parameters.
		handler = requestHandler.bind(null, proxyServer, proxyInfo);

		// Create a server listening on the specified port with our custom handler.
		if (proxyInfo.useSsl) {
			httpsServerOptions.pfx = fs.readFileSync(config.certificatePath);
			httpsServerOptions.passphrase = config.certificatePassphrase;
			https.createServer(httpsServerOptions, handler).listen(proxyInfo.port);
		}
		else {
			console.warn(util.format("WARNING: The proxy on port %s is not configured to use SSL; credentials will be sent in clear text!", proxyInfo.port));
			http.createServer(handler).listen(proxyInfo.port);
		}
	});

	console.log("Startup complete; waiting for requests...");
}());