# This is the full version of the example in the readme.

import requests.exceptions
import acme.messages

from free_tls_certificates import client

# Set this to the list of domain names for the certificate. The
# first will be the "common name" and the rest will be Subject
# Alternative Names names. The difference doesn't really matter.
# You can have just a single domain here.
#
# You'll need to replace the domain with a real domain. Let's Encrypt
# won't even try on an invalid domain name (.tld is not real), and
# please be respectful and don't put in a domain name you don't own.
domains = ["invalid-test-domain.tld"]

agree_to_tos = None  # fill this in on second run per output of exception

try:
    client.issue_certificate(
        domains,
        "path/to/some/storage",
        certificate_file="certificate.crt",
        agree_to_tos_url=agree_to_tos)

except client.AccountDataIsCorrupt as e:
	# This is an extremely rare condition.
	print("The account data stored in", e.account_file_path, "is corrupt.")
	print("You should probably delete this file and start over.")

except client.NeedToAgreeToTOS as e:
    print("You need to agree to the TOS. Set this on next run:")
    print("agree_to_tos =", repr(e.url))

except client.InvalidDomainName as e:
	# One of the domain names provided is not a domain name the ACME
	# server can issue a certificate for.
	print(e)

except client.NeedToTakeAction as e:
    for action in e.actions:
        if isinstance(action, client.NeedToInstallFile):
            print("Install a file!")
            print("Location:", action.url) # action.file_name is just the final filename portion
            print("Content Type:", action.content_type)
            print("Contents:", action.contents)
            print()

except client.WaitABit as e:
    import datetime
    print ("Try again in %s." % (e.until_when - datetime.datetime.now()))

except client.RateLimited as e:
    # The ACME server is refusing to issue more certificates for a second-level domain
    # for your account.
    print(e)

except acme.messages.Error as e:
    # A protocol error occurred. If a CSR was supplied, it might
    # be for a different set of domains than was specified, for instance.
    print("Something went wrong:", e)

except requests.exceptions.RequestException as e:
    # A DNS or network error occurred.
    print("Something went wrong:", e)
