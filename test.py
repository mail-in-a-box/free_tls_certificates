from letsencrypt_simpleclient.client import issue_certificate, NeedToAgreeToTOS, NeedToInstallFile, WaitABit

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
        certificate_file="certificate.crt",
        agree_to_tos_url=agree_to_tos)

try:
    try:
        do_issue()
    except NeedToAgreeToTOS as e:
        print("Automatically agreeing to TOS at", e.url)
        agree_to_tos = e.url
        do_issue()
except NeedToInstallFile as e:
    print("Install a file")
    print("Location:", e.url)
    print("Content Type:", e.content_type)
    print("Contents:", e.contents)
except WaitABit as e:
    import datetime
    print ("Try again in %s." % (e.until_when - datetime.datetime.now()))
