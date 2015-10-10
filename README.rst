Let's Encrypt Simple Client
===========================

__This is a work in progress.__

This is a simple Python client library for Let's Encrypt, or any ACME server that issues SSL certificates, based on the acme client library.

The purpose of this library is to make it easier to embed Let's Encrypt within server provisioning applications (without resorting to shelling out the letsencrypt command line client).

Prerequisites:

* The Let's Encrypt ``ACME client library``<https://github.com/letsencrypt/letsencrypt/tree/master/acme> and all of its dependencies.

Example::

    import requests.exceptions
    import acme.messages

    from letsencrypt_simpleclient.client import issue_certificate, NeedToAgreeToTOS, NeedToInstallFile, NeedToTakeAction, WaitABit

    # Set this to the list of domain names for the certificate. The
    # first will be the "common name" and the rest will be Subject
    # Alternative Names names. The difference doesn't really matter.
    # You can have just a single domain here.
    domains = ["mailinabox.email", "www.mailinabox.email"]

    agree_to_tos = None  # fill this in on second run per output of exception

    try:
        issue_certificate(
            domains,
            "path/to/some/storage",
            certificate_file="certificate.crt",
            agree_to_tos_url=agree_to_tos)
    except NeedToAgreeToTOS as e:
        print("You need to agree to the TOS. Set this on next run:")
        print("agree_to_tos =", repr(e.url))
    except NeedToTakeAction as e:
        for action in e.actions:
            if isinstance(action, NeedToInstallFile):
                print("Install a file!")
                print("Location:", action.url)
                print("Content Type:", action.content_type)
                print("Contents:", action.contents)
                print()
    except WaitABit as e:
        import datetime
        print ("Try again in %s." % (e.until_when - datetime.datetime.now()))
    except acme.messages.Error as e:
        # A protocol error occurred. If a CSR was supplied, it might
        # be for a different set of domains than was specified, for instance.
        print("Something went wrong:", e)
    except requests.exceptions.RequestException as e:
        # A DNS or network error occurred.
        print("Something went wrong:", e)

Testing
--------

To test the library, set up a locally running Boulder server, which is the reference implementation of an ACME server.

* Download the Boulder source code from https://github.com/letsencrypt/boulder.
* Install docker.
* Run ``./test/run-docker.sh`` (perhaps with sudo depending on your docker setup).

Boulder runs in its test configuration by default which performs Simple HTTP domain validation by querying the host machine on port 5001 no matter what domain a certificate is being requested for, which is handy for creating a test server to respond to those requests. (You still have to test with a valid public domain name, however, so ``something.invalid`` will be rejected by your Boulder server.)

Create a virtual environment for testing if you don't already have one::

    virtualenv -ppython3 env
    source env/bin/activate

Add ``127.0.0.1 localhost.test-domain.invalid.xyz`` to your ``/etc/hosts`` file (this is so that client-side verification that the domain validation check is in place can succeed).

Start our unit test::

    python test.py

This checks that the local Boulder server will issue a certificate for an arbitrary domain.
