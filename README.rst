A Simple Let's Encrypt (ACME) Client
====================================

``free_tls_certificates`` is a Python 2/3 client library and command-line client for `Let's Encrypt <https://letsencrypt.org/>`_ (or any `ACME <https://github.com/letsencrypt/acme-spec>`_ server) to automatically provision `TLS <https://en.wikipedia.org/wiki/Transport_Layer_Security>`_ certificates (aka SSL certificates).

The purpose of this library is to make it easier to embed Let's Encrypt within server provisioning applications without resorting to shelling out `certbot <https://certbot.eff.org>`_ as root. You can also use this library as a command-line client like certbot, but it does not require root privs to run. Instead, you are responsible for having a web server running.

Installation
------------

``free_tls_certificates`` can be installed via pip but it requires some of its dependencies' binary dependencies to be installed first. On Ubuntu (and using Python 3 as an example)::

    sudo apt-get install build-essential libssl-dev libffi-dev python3-dev python3-pip
    sudo pip3 install free_tls_certificates

The dependencies that pip will install are:

* Let's Encrypt's low-level `ACME client library <https://github.com/letsencrypt/letsencrypt/tree/master/acme>`_ and all of `its dependencies <https://github.com/letsencrypt/letsencrypt/blob/master/acme/setup.py#L9>`_.
* `idna <https://github.com/kjd/idna>`_ by kjd.
* `cryptography <https://github.com/pyca/cryptography>`_ and its dependencies (on Ubuntu: ``sudo apt-get install build-essential libssl-dev libffi-dev python3-dev``).

Command-Line Usage
------------------

The command-line tool ``free_tls_certificate`` (which becomes available after pip-installing ``free_tls_certificates``, which has an ``s``) can be used to automatically provision a TLS certificate from Let's Encrypt or generate a self-signed certificate.

To provision a TLS certificate from Let's Encrypt, you will need to have a web server already running on port 80 (not 443 --- domain validation only works on port 80) and access to its static root from the machine you are going to run ``free_tls_certificates`` on.

Run::

    free_tls_certificate domain-name-1.com [domain-name-2.com ...] /path/to/private.key /path/to/certificate.crt /path/to/website /path/to/acme/storage

On the first run:

* A new 2048-bit RSA private key will be generated and saved in ``/path/to/private.key``, unless a file exists at that path, in which case that private key will be used.

* You'll be prompted to accept the Let's Encrypt terms of service. A new ACME account will be created and maintained for you in ``/path/to/acme/storage``.

* An ACME HTTP01 challenge will be requested, a domain ownership verification file will be installed in ``/path/to/website/.well-known/acme-challenge/...``, and when the certificate is ready it will be written to ``/path/to/certificate.crt``.

Subsequent runs will be headless and will just do the right thing:

* If certificate file specified exists and is valid for the domains given for at least 30 days, the tool will exit without doing anything (with exit code ``3``). 

* If the certificate file doesn't exist, isn't valid for all of the domains given, is self-signed, or is expiring within 30 days, a new certificate will be issued and the certificate file will be overwritten. (You are responsible for then restarting your web server so it sees the new certificate.)

Since the tool will only issue a new certificate when needed, you can run the tool in a nightly cron job to keep your certificate valid.

You can also use the tool to generate a self-signed certificate. This is handy when spinning up a new machine: Your web server probably won't start until you have a certificate file in place, but you can't get a certificate until your web server is running.

To get a self-signed certificate, just add ``--self-signed``::

    free_tls_certificate --self-signed domain-name-1.com [domain-name-2.com ...] /path/to/private.key /path/to/certificate.crt

Web Server Support
------------------

You need to have a web server running that is serving a directory of static files that ``free_tls_certificate`` can write to. It must serve the files over HTTP (port 80) as ACME domain validation does not occur over HTTPS.

You might want to use an ``nginx`` configuration like this (or the equivalent for your web stack)::

    server {
        listen 80 default;
        location / {
            # Redirect to HTTPS.
            return 301 https://$host$request_uri;
        }
        location /.well-known/acme-challenge/ {
            # Serve the Let's Encrypt challenge path (must be
            # over HTTP, not HTTPS).
            root /home/ubuntu/public_html;
        }
    }

    server {
        listen 443 ssl http2;
        server_name domin-name-1.com;
        ssl_certificate /path/to/certificate.crt;
        ssl_certificate_key /path/to/private.key;
        ... your other directives here...
    }

In this case, your ``/path/to/website`` would be ``/home/ubuntu/public_html``.

Usage as Python Module
----------------------

The file `driver.py <free_tls_certificates/driver.py>`_ contains a complete, working example for how to use this client library. It is the code behind the ``free_tls_certificate`` command-line tool.

See `driver.py <free_tls_certificates/driver.py>`_ for complete documentation. There are a number of edge cases to handle.

Here's basically how it works. You would adapt this code for your server provisioning tool::

    import requests.exceptions
    import acme.messages

    from free_tls_certificates import client

    domains = ["mailinabox.email", "www.mailinabox.email"]
    agree_to_tos = None  # fill this in on second run per output of exception

    try:
        client.issue_certificate(
            domains,
            "path/to/some/storage",
            certificate_file="certificate.crt",
            agree_to_tos_url=agree_to_tos)

    except client.NeedToAgreeToTOS as e:
        print("You need to agree to the TOS. Set this on next run:")
        print("agree_to_tos = " + repr(e.url))

    except client.NeedToTakeAction as e:
        for action in e.actions:
            if isinstance(action, client.NeedToInstallFile):
                print("Install a file!")
                print("Location: " + action.url)
                print("Contents: " + action.contents)

    except client.WaitABit as e:
        import datetime
        print ("Try again in %s." % (e.until_when - datetime.datetime.now()))

But see the full driver file for all of the error conditions you need to handle!


Usage Notes
-----------

You can request a certificate for multiple domains at once, probably up to 100 (which is Let's Encrypt's current maximum). The first domain you specify will be put into the certificate's "common name" field, and all will be put into the certificate's Subject Alternative Name (SAN) extension. (All modern browsers accept SAN domains.)

Note that Let's Encrypt doesn't yet (at the time of writing) support issuing certificates for internationalized domains.

You may use any Python string type (``str``, ``bytes``, ``unicode``) to pass domain names. If a domain is internationalized, use Python 2 ``unicode`` and Python 3 ``str`` instances to pass the Unicode form of the domain name. If the string is already IDNA-encoded (i.e. punycode), you may use any string type.


Testing
--------

To test the library, set up a locally running Boulder server, which is the reference implementation of an ACME server.

* Install docker.
* Download the Boulder source code from https://github.com/letsencrypt/boulder.
* Change to the directory that you put Boulder in.
* Run ``FAKE_DNS=$(hostname -I) test/run-docker.sh`` (perhaps with sudo depending on your docker setup).

Boulder runs in its test configuration by default which performs "HTTP01" domain validation by querying the docker host machine on port 5002 no matter what domain a certificate is being requested for, which is handy for creating a test server to respond to those requests. (You still have to test with a plausible public domain name, however, so ``something.invalid`` will be rejected by your Boulder server.)

Create a virtual environment for testing if you don't already have one::

    virtualenv -ppython3 env
    source env/bin/activate
    pip install -r requirements.txt

Add::

	127.0.0.1 x1.le.wtf
	127.0.0.1 fail.le.wtf

to your ``/etc/hosts`` file. This is for our library's client-side verification of the domain validation check, prior to submission of the challenge response to the ACME server. We use x1.le.wtf and fail.le.wtf as test domains (because boulder won't issue certificates for invalid domain names, even in testing) that must resolve to localhost.

Start our unit test::

    python test.py

This checks that the local Boulder server will issue a certificate for ``x1.le.wtf``, and it checks other aspects of the library.
