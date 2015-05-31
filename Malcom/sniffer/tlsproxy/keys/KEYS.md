# Generating TLS keys and x509 certificates with OpenSSL

The goal is to generate a self-signed certificate that Malcom can use for intercepting TLS flows.
Ideally, we should generate a CA certificate and incorporate it to the Windows store so that the certificate is accepted by default. I'll see if I can get to that later. For now, follow these instructions.

Make sure you have the OpenSSL library installed in your system before proceeding.

These instructions have been taken from [here](http://www.akadia.com/services/ssh_test_certificate.html).

## Creating self-signed certificates

* Generate a private key

	
        $ openssl genrsa -des3 -out server.key 1024

        Generating RSA private key, 1024 bit long modulus
        ......++++++
        ...........++++++
        e is 65537 (0x10001)
        Enter pass phrase for server.key:
        Verifying - Enter pass phrase for server.key:

No need to worry about the complexity of the passphrase - we're going to remove it later anyways.

* Generate a CSR (Certificate Signing Request)

        $ openssl req -new -key server.key -out server.csr
        
        Enter pass phrase for server.key:
        You are about to be asked to enter information that will be incorporated
        into your certificate request.
        What you are about to enter is what is called a Distinguished Name or a DN.
        There are quite a few fields but you can leave some blank
        For some fields there will be a default value,
        If you enter '.', the field will be left blank.
        -----
        Country Name (2 letter code) [AU]:
        State or Province Name (full name) [Some-State]:
        Locality Name (eg, city) []:
        Organization Name (eg, company) [Internet Widgits Pty Ltd]:
        Organizational Unit Name (eg, section) []:
        Common Name (e.g. server FQDN or YOUR name) []:
        Email Address []:
        
        Please enter the following 'extra' attributes
        to be sent with your certificate request
        A challenge password []:
        An optional company name []:

* Remove the passphrase from your key

        $ cp server.key server.key.org
        $ openssl rsa -in server.key.org -out server.key

This should create a passphrase-less `server.key` file.

* Generate the self-signed certificate

        $ openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
        
        Signature ok
        subject=/C=/ST=/L=/O=/OU=/CN=/Email=
        Getting Private key

There you go, `server.key` and `server.crt` are the two files used by Malcom to provide a certificate and intercept TLS communications. Make sure these two are present in the `keys` directory. Happy snooping!




