A Simple Let's Encrypt (ACME) Client
====================================

**This is a work in progress!**

``free_tls_certificates`` is a Python 2/3 client library for `Let's Encrypt <https://letsencrypt.org/>`_ or any ACME server that issues `TLS <https://en.wikipedia.org/wiki/Transport_Layer_Security>`_ certificates (aka SSL certificates). The purpose of this library is to make it easier to embed Let's Encrypt within server provisioning applications without resorting to shelling out the ``letsencrypt`` command line client.

This module is based on the low-level `acme <https://github.com/letsencrypt/letsencrypt/tree/master/acme>`_ client library by the Let's Encrypt team.

Installation::

	pip install free_tls_certificates

Prerequisites:

* The Let's Encrypt `ACME client library <https://github.com/letsencrypt/letsencrypt/tree/master/acme>`_ and all of `its dependencies <https://github.com/letsencrypt/letsencrypt/blob/master/acme/setup.py#L9>`_.
* The ``idna`` module (https://github.com/kjd/idna).
* The ``cryptography`` module (https://github.com/pyca/cryptography) and its dependencies (on Ubuntu: ``sudo apt-get install build-essential libssl-dev libffi-dev python3-dev``).

Usage:

The file `driver.py <free_tls_certificates/driver.py>`_ contains a complete, working example for how to use this client library. It is also a convenient command-line tool for provisioning a certificate, which after pip-installing the package becomes available as ``free_tls_certificate``.

From the command line::

    sudo apt-get install build-essential libssl-dev libffi-dev python3-dev python3-pip
    sudo pip3 install free_tls_certificates
    free_tls_certificate domain-name-1.com [domain-name-2.com ...] private.key certificate.crt /path/to/website /path/to/acme/storage

See `driver.py <free_tls_certificates/driver.py>`_ for complete documentation.

Here's basically how it works:

Example::

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

But see the full driver file for all of the error conditions you need to handle.

Usage Notes
-----------

You may use any Python string type (``str``, ``bytes``, ``unicode``) to pass domain names. If a domain is internationalized, use Python 2 ``unicode`` and Python 3 ``str`` instances to pass the Unicode form of the domain name. If the string is already IDNA-encoded (i.e. punycode), you may use any string type.

Note that Let's Encrypt doesn't yet (at the time of writing) support issuing certificates for internationalized domains.

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
