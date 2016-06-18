#!/usr/bin/python3
# This is a complete, working example for using this module as
# an ACME client. It's also a convenient tool for provisioning
# a TLS certificate from the command line.
#
# Usage:
#
# python(3) driver.py domain-name-1.com [domain-name-2.com ...] private.key certificate.crt /path/to/website /path/to/acme/storage
#
# Options:
#
#   Options must come before all other arguments. All options are
#   optional.
#
#   --server [staging | url]
#   Either the special token "staging" or a URL to an ACME server
#   like "https://acme-staging.api.letsencrypt.org/directory".
#
# The driver will install a domain validation challenge file
# into /path/to/website/.well-known/acme-challenge/ and
# then request a certificate from Let's Encrypt for all of the
# domain names specified on the command line.
#
# If more than one domain name is given, the first becomes the
# certificates "common name." The remainder become "subject
# alternative names" in the certificate.
#
# If the private key file does not already exist, one is created
# and saved for you.
#
# If the certificate.crt file already exists and is valid for
# all of the domain names specified on the command line for at
# least 30 days, then this program exits immediately because
# the certificate is already good. If the certificate needs to
# be renewed (i.e. <=30 days), the file is overwritten with a
# new certificate. So you can put this script into a cron job
# and it will do the right thing.
#
# The last argument, /path/to/acme/storage, is where this program
# can store your Let's Encrypt account data. The data should be
# kept from run to run. The directory will be created if it doesn't
# exist.
#
# On the first run, you'll be asked interactively to agree to
# Let's Encrypt's terms of service agreement.

import os
import os.path
import sys
import time
import datetime

def parse_command_line():
    # Drop the 0th arg which is the program name. Sanity check.
    args = sys.argv[1:]
    if len(args) < 3:
        raise Exception("Not enough command-line arguments.")

    # Parse optional options.
    from free_tls_certificates.client import LETSENCRYPT_SERVER, LETSENCRYPT_STAGING_SERVER
    acme_server = LETSENCRYPT_SERVER
    self_signed = False
    append_well_known_acme_challenge = True
    while True:
        if args[0] == "--server":
            args.pop(0)
            acme_server = args.pop(0)
            if acme_server == "staging":
                acme_server = LETSENCRYPT_STAGING_SERVER
            continue
        if args[0] == "--self-signed":
            args.pop(0)
            self_signed = True
            acme_server = "https://domain.invalid" # should be ignored
            continue
        if args[0] == "--is-well-known-path":
            args.pop(0)
            append_well_known_acme_challenge = False
            continue
        break

    # Get the ACME arguments.
    if not self_signed:
        if len(args) < 2:
            raise Exception("Not enough command-line arguments.")
        
        acme_account_path = args.pop(-1)
        static_path = args.pop(-1)

        if append_well_known_acme_challenge:
            # Add .well-known/acme-challenge to what is given on the command-line.
            static_path = os.path.join(static_path, '.well-known', 'acme-challenge')

        # Create account storage directory if necessary.
        try:
            os.makedirs(acme_account_path)
        except OSError:
            # directory already exists
            pass

    else:
        # If we're just generating a self-signed certificate, then
        # these aren't used.
        acme_account_path = None
        static_path = None

    # Split remaining arguments.
    if len(args) < 3:
        raise Exception("Not enough command-line arguments.")
    domains = args[0:-2]
    private_key_fn, certificate_fn = args[-2:]

    # Return options.
    return {
        "acme_server": acme_server,
        "domains": domains,
        "private_key_fn": private_key_fn,
        "certificate_fn": certificate_fn,
        "static_path": static_path,
        "acme_account_path": acme_account_path,
        "self_signed": self_signed,
    }


def stop_if_certificate_valid(opts):
    # Stop if the certificate is already valid for all of the domains.
    import idna

    if not os.path.exists(opts["certificate_fn"]):
        if sys.stdin.isatty():
           sys.stderr.write("Certificate file %s not present...\n" % opts["certificate_fn"])
        return

    def idna_encode(domain):
        # squash exceptions here
        try:
            return idna.encode(domain).decode("ascii")
        except:
            return domain

    # Load the certificate.
    from free_tls_certificates.utils import load_certificate, get_certificate_domains
    cert = load_certificate(opts["certificate_fn"])

    # If this is a self-signed certificate (and the user is seeking
    # a real one), provision a new one.
    if cert.issuer == cert.subject and not opts["self_signed"]:
        if sys.stdin.isatty():
           sys.stderr.write("Replacing self-signed certificate...\n")
        return

    # If this is expiring within 30 days, provision a new one.
    expires_in = cert.not_valid_after - datetime.datetime.now()
    if expires_in < datetime.timedelta(days=30):
        if sys.stdin.isatty():
           sys.stderr.write("Replacing expiring certificate (expires in %s)...\n" % str(expires_in))
        return

    # If the certificate is not valid for one of the domains we're requesting,
    # provision a new one.
    request_domains = set(idna_encode(domain) for domain in opts["domains"])
    cert_domains = set(get_certificate_domains(cert))
    if len(request_domains - cert_domains) > 0:
        if sys.stdin.isatty():
           sys.stderr.write("Certificate is not valid for %s (found %s)...\n" % (
               ", ".join(x.decode('ascii') for x in (request_domains - cert_domains)),
               ", ".join(x.decode('ascii') for x in cert_domains)
               ))
        return

    # Certificate is valid for the requested domains - no need to provision.
    if sys.stdout.isatty():
        print("Certificate is already valid and good for at least 30 days.")
    sys.exit(3)


def provision_certificate(opts):
    from free_tls_certificates import client
    import requests.exceptions
    import acme.messages

    def logger(msg):
        print(msg)

    # It takes multiple invokations of client.issue_certificate to get the job done.
    agree_to_tos_url = None
    has_installed_files = False
    while True:
        try:
            # Issue request.
            client.issue_certificate(
                opts["domains"],
                opts["acme_account_path"],
                certificate_file=opts["certificate_fn"],
                private_key_file=opts["private_key_fn"],
                agree_to_tos_url=agree_to_tos_url,
                acme_server=opts["acme_server"],
                self_signed=opts["self_signed"],
                logger=logger)

            # A certificate was provisioned!
            return

        ###########################################################################################
        except client.AccountDataIsCorrupt as e:
            # This is an extremely rare condition.
            print("The account data stored in " + e.account_file_path + " is corrupt.")
            print("You should probably delete this file and start over.")
            sys.exit(1)

        ###########################################################################################
        except client.NeedToAgreeToTOS as e:
            # Can't ask user a question interactively if device is not a TTY.
            if not sys.stdin.isatty():
                sys.stderr.write("You must agree to the Let's Encrypt TOS but input is not a TTY.\n")
                sys.exit(2)

            sys.stdout.write("""Please open this document in your web browser:

%s

It is Let's Encrypt's terms of service agreement. If you agree, I can
provision your TLS certificate. If you don't agree, this program stops.

Do you agree to the agreement? Type Y or N and press <ENTER>: """
                 % e.url)
            sys.stdout.flush()
            
            if sys.stdin.readline().strip().upper() != "Y":
                print("\nYou didn't agree. Quitting.")
                sys.exit(1)

            # Okay, indicate agreement on next iteration.
            agree_to_tos_url = e.url

            # Try again.
            continue

        ###########################################################################################
        except client.InvalidDomainName as e:
            # One of the domain names provided is not a domain name the ACME
            # server can issue a certificate for.
            print(e)
            sys.exit(1)

        ###########################################################################################
        except client.NeedToTakeAction as e:
            for action in e.actions:
                if not isinstance(action, client.NeedToInstallFile):
                    raise Exception()

                fn = os.path.join(opts['static_path'], action.file_name)

                # Prevent infinite looping.
                if has_installed_files:
                    print("""
A domain validation challenge file was installed but we couldn't see it on the
second pass. That usually means that the domain name does not resolve to the
machine this program is running on, or the web server is not serving the static
path you specified. Make sure %s
is serving the file at %s.""" % (action.url, fn))
                    sys.exit(1)


                print("Install domain validation challenge file at " + action.url)

                # Ensure the static path exists.
                try:
                    os.makedirs(opts['static_path'])
                except OSError:
                    # directory already exists
                    pass

                # Write file.
                with open(fn, 'w') as f:
                    f.write(action.contents)

            # Try again.
            has_installed_files = True
            continue

        ###########################################################################################
        except client.WaitABit as e:
            # ACME server tells us to try again in a bit.
            while e.until_when > datetime.datetime.now():
                print ("We have to wait %d more seconds for the certificate to be issued..."
                    % int(round((e.until_when - datetime.datetime.now()).total_seconds())))
                time.sleep(15)

            # Try again.
            continue

        ###########################################################################################
        except client.RateLimited as e:
            # The ACME server is refusing to issue more certificates for a second-level domain
            # for your account.
            print(e)
            sys.exit(1)

        ###########################################################################################
        except acme.messages.Error as e:
            # A protocol error occurred. (If a CSR was supplied, it might
            # be for a different set of domains than was specified, for instance.)
            print("Something went wrong: " + str(e))
            sys.exit(1)

        ###########################################################################################
        except requests.exceptions.RequestException as e:
            # A DNS or network error occurred.
            print("Something went wrong:" + str(e))
            sys.exit(1)

def main():
    opts = parse_command_line()
    stop_if_certificate_valid(opts)
    provision_certificate(opts)
    return 0

if __name__ == "__main__":
    main()

