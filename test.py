import requests.exceptions
import acme.messages

from letsencrypt_simpleclient.client import issue_certificate, \
    SimpleHTTP, \
    NeedToAgreeToTOS, NeedToInstallFile, NeedToTakeAction, WaitABit

# Set this to the list of domain names for the certificate. The
# first will be the "common name" and the rest will be Subject
# Alternative Names names. The difference doesn't really matter.
# You can have just a single domain here.
domains = ["mailinabox.email", "www.mailinabox.email"]

agree_to_tos = None  # fill this in on second run per output of exception

def do_issue():
    issue_certificate(
        domains,
        "path/to/some/storage",
        validation_method=SimpleHTTP(True), # optional, this is the default
        certificate_file="certificate.crt", # optional, nothing written if not specified
        certificate_chain_file="chain.crt", # optional, default is to append to certificate_file
        agree_to_tos_url=agree_to_tos)

try:
    try:
        do_issue()
    except NeedToAgreeToTOS as e:
        print("Automatically agreeing to TOS at", e.url)
        agree_to_tos = e.url
        do_issue()
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
    print("Try again in %s." % (e.until_when - datetime.datetime.now()))
except acme.messages.Error as e:
    # A protocol error occurred. If a CSR was supplied, it might
    # be for a different set of domains than was specified, for instance.
    print("Something went wrong:", e)
except requests.exceptions.RequestException as e:
    # A DNS or network error occurred.
    print("Something went wrong:", e)
