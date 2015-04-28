# checkip
Stand-alone, secure and scalable web server which returns the IP address of caller

Checkip is a single minded webserver.  It serves a single URI "/" and returns the following web page

```
<html>
  <head>
    <title>Current IP Check</title>
  </head>
  <body>
    Current IP Address: 123.123.123.123
  </body>
</html>
```

It serves this page blazingly fast - with a response time of under 10mS. This means that checkip can easily service 100 requests per second using its single thread.  This means that it can handle upto 30,000 clients, each checking their IP address every 5 minutes.  Since checkip is based on the widely used mongoose embeded web server, it can easily be enabled to use multiple threads enabling it to be scaled to support millions of clients.

- Checkip has been designed with security in mind.  The server runs in a chroot jail under a unpriveleged userid. It rigorously validates every HTTP request, rejecting any request with bad URI's or headers.

- It supports SSL (TLS1.2 only, and SSLv2/v3/TLS1.0 are disabled)

- It write status messages to syslog

## Options

checkip -d -p nnn -j /path/to/chroot -u userid

  -d	Run as daemon

  -j /path/to/chroot
	Checkip with run in a chroot jail, with the new root set to`/path/to/chroot`

  -u userid
	Run as userid.  The default is user nobody

  -p <port list>
        List on the following ports.  Checkip uses a mongoose style for ports.  The default is
	`80,ssl://443:server-cert.pem`, which will listen using http on port 80 and https on 443.

	The file `server-ceret.pem` must contain both the x509 certificate and the private key.


## Dependencies

To install checkip, you will require the OpenSSL libraries
