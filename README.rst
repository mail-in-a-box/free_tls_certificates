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
        print("Somethig went wrong:", e)
    except requests.exceptions.RequestException as e:
        # A DNS or network error occurred.
        print("Somethig went wrong:", e)

