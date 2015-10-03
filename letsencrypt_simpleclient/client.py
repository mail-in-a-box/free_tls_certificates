# Get SSL certificates from Let's Encrypt (letsencrypt.org).
# ----------------------------------------------------------

import os.path
import json
import datetime
import time
import acme.client
import acme.messages
import acme.challenges

ACME_SERVER = "https://acme-staging.api.letsencrypt.org/directory"
ACCOUNT_KEY_SIZE = 2048
EXPIRY_BUFFER_TIME = 60 * 60 * 24 * 2  # two days


def main():
    # Set this to the list of domain names for the certificate. The
    # first will be the "common name" and the rest will be Subject
    # Alternative Names names. The difference doesn't really matter.
    # You can have just a single domain here.
    domains = ["mailinabox.email", "www.mailinabox.email"]

    account_key_file = 'le_account.pem'
    registration_file = "le_registration.json"
    challenges_file = "le_challenges.jsons"
    certificate_file = "certificate.crt"

    def simple_logger(s):
        print(s)

    # Create the ACME client, making a new account & registration
    # if not set up yet.
    try:
        (client, regr, account) = create_client(account_key_file, registration_file, simple_logger)
    except NeedToAgreeToTOS as e:
        print("agreeing to TOS", e.url)
        (client, regr, account) = create_client(account_key_file, registration_file, simple_logger, agree_to_tos_url=e.url)

    # Submit domain validation.
    challgs = []
    for domain in domains:
        try:
            challg = submit_domain_validation(client, regr, account, challenges_file, domain, simple_logger)
            challgs.append(challg)
        except NeedToInstallFile as e:
            print("Install a file")
            print("Location:", e.url)
            print("Content Type:", e.content_type)
            print("Contents:", e.contents)
            return
        except WaitABit as e:
            print ("Try again in %s." % (e.until_when - datetime.datetime.now()))
            return

    # Domains are now validated. Generate a CSR.

    # Since this is an example, we'll generate a private key on the fly.
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # To save it in PEM format (but for this test we don't need to save it):
    #
    # with open(keyfile, 'wb') as f:
    #   f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL)))
    #
    # If you already have a private key but not a CSR, load it like this:
    #
    # with open(keyfile, 'rb') as f:
    #   key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Create a CSR, if you don't have one already.
    csr = generate_csr(domains, key)

    # Or if you already have a CSR, load it now in PEM format:
    #
    # with open(csrfile, 'rb') as f:
    #   csr = f.read()
    # csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)

    # Request a certificate using the CSR and some number of domain validation challenges.
    cert_response = client.request_issuance(csr, challgs)

    # cert_response.body now holds a OpenSSL.crypto.X509 object. Convert it to
    # PEM format and save:
    import OpenSSL.crypto
    cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_response.body)
    with open(certificate_file, 'wb') as f:
        f.write(cert_pem)


class NeedToAgreeToTOS(Exception):
    def __init__(self, url):
        self.url = url


class NoChallengeMethodsSupported(Exception):
    pass


class ChallengesUnknownStatus(Exception):
    pass


class WaitABit(Exception):
    def __init__(self, until_when):
        self.until_when = until_when


class NeedToInstallFile(Exception):
    def __init__(self, url, contents, content_type):
        self.url = url
        self.contents = contents
        self.content_type = content_type


# Set up the ACME client object by loading/creating an account key
# and registering or validating an existing registration.
def create_client(account_key_file, registration_file, log, agree_to_tos_url=None):
    # Get or generate the Let's Encrypt account key.
    key = load_or_generate_private_key(account_key_file, log)

    # Create the client.
    client = acme.client.Client(ACME_SERVER, key)

    # Register or validate and update our registration.
    regr = register(registration_file, client, log, agree_to_tos_url=agree_to_tos_url)

    # We need to agree to the TOS if we haven't done so
    # already. To do that, re-call this method with
    # agree_to_tos_url set to the URL of the agreement
    # that was given in the 'url' field of the
    # NeedToAgreeToTOS exception.
    if not regr.body.agreement:
        raise NeedToAgreeToTOS(regr.terms_of_service)

    return (client, regr, key)


# Get a RSA private key and returns it as a jose.JWKRSA object,
# loading it from keyfile if the file exists, otherwise generating
# a new key and writing it to that file.
def load_or_generate_private_key(keyfile, log):
    from acme import jose
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    if os.path.exists(keyfile):
        # Load from file.
        log("Reading account key from %s." % keyfile)
        with open(keyfile, 'rb') as f:
            pem = f.read()
            key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    else:
        # Generate new key and write to file.
        log("Generating a new account key.")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=ACCOUNT_KEY_SIZE,
            backend=default_backend())

        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(keyfile, 'wb') as f:
            f.write(pem)

    key = jose.JWKRSA(key=jose.ComparableRSAKey(key))

    return key


def register(storage, client, log, agree_to_tos_url=None):
    existing_regr = None
    if not os.path.exists(storage):
        # Create a new registration.
        log("Registering a new account with Let's Encrypt.")
        regr = client.register()
    else:
        log("Validating existing account saved to %s." % storage)

        # Validate existing registration by querying for it from the server.
        with open(storage, 'r') as f:
            regr = acme.messages.RegistrationResource.json_loads(f.read())
        existing_regr = regr.json_dumps()
        regr = client.query_registration(regr)

    # If this call is to agree to a terms of service agreement, update the
    # registration.
    if agree_to_tos_url:
        regr = client.update_registration(regr.update(body=regr.body.update(agreement=agree_to_tos_url)))

    # Write new or updated registration (if it changed, and hopefully json_dumps is stable).
    if existing_regr != regr.json_dumps():
        if existing_regr is not None:
            log("Saving updated account information.")
        with open(storage, 'w') as f:
            f.write(regr.json_dumps_pretty())

    return regr


def submit_domain_validation(client, regr, account, challenges_file, domain, log):
    # Get challenges for the domain.
    challg1 = get_challenges(client, regr, domain, challenges_file, log)
    challg = challg1.body

    if challg.status.name == "valid":
        # This is already valid. Return it immediately.
        return challg1
    elif challg.status.name != "pending":
        raise ChallengesUnknownStatus()

    # Look for a challenge combination that we can fulfill.
    for combination in challg.combinations:
        if len(combination) == 1:
            chg = challg.challenges[combination[0]]
            if isinstance(chg.chall, acme.challenges.SimpleHTTP):
                if chg.status.name != "pending":
                    # We can't submit twice. If this challenge is still pending
                    # but the overall challg object is not valid, then I'm not
                    # sure how to proceed.
                    raise ChallengesUnknownStatus()

                # Submit the SimpleHTTP challenge, raising NeedToInstallFile if
                # the conditions are not yet met.
                chg = answer_challenge_simplehttp(
                    domain,
                    chg.chall,
                    client,
                    account,
                    chg,
                    log)

                # The ChallengeResource probably comes back still pending because
                # it doesn't go THAT fast. Give it a moment, then poll.
                time.sleep(1)
                challg1, resp = client.poll(challg1)
                if challg1.body.status.name == "valid":
                    # It's valid now. That was fast.
                    return challg1

                # It's not valid. Tell the user they must want.
                retry_after = client.retry_after(resp, default=60)
                raise WaitABit(retry_after)

    raise NoChallengeMethodsSupported()


def get_challenges(client, regr, domain, challenges_file, log):
    # Load any existing challenges we've requested for domains so we
    # can track the challenges we've requested across sessions.
    existing_challenges = []
    if os.path.exists(challenges_file):
        with open(challenges_file) as f:
            existing_challenges = json.load(f)

    # Load.
    for i in range(len(existing_challenges)):
        existing_challenges[i] = \
            acme.messages.AuthorizationResource.from_json(existing_challenges[i])

    # Drop any challenges that have expired.
    existing_challenges = list(filter(lambda challg: is_still_valid(challg.body.expires), existing_challenges))

    # If challenges exist for this domain, reuse it.
    for i, challg in enumerate(existing_challenges):
        if challg.body.identifier.typ.name == "dns" and challg.body.identifier.value == domain:
            log("Reusing existing challenges for %s." % domain)

            # Refresh the record because it may have been updated with validated challenges.
            challg, resp = client.poll(challg)
            existing_challenges[i] = challg
            break
    else:
        # None found.
        challg = None

    if challg is None:
        # Get new challenges for a domain.
        log("Requesting new challenges for %s." % domain)
        challg = client.request_domain_challenges(domain, regr.new_authzr_uri)

        # Add into our existing challenges.
        existing_challenges.append(challg)

    # Save new set of challenges.
    with open(challenges_file, 'w') as f:
        f.write(json.dumps([c.to_json() for c in existing_challenges], sort_keys=True, indent=4))

    # Return the new challenges for this domain.
    return challg


def is_still_valid(expires_dt):
    # Make sure the datetime is at least two days into the future,
    # to give us enough time to actually perform the challenge and
    # not have to worry about timezone conversion.
    # This is a really bad date comparison that loses timezone info.
    return (expires_dt.replace(tzinfo=None) - datetime.datetime.utcnow()) > datetime.timedelta(seconds=EXPIRY_BUFFER_TIME)


def answer_challenge_simplehttp(domain, chall, client, account, challg_body, log):
    # Create a challenge response.
    resp = acme.challenges.SimpleHTTPResponse(tls=True)

    # See if we've already installed the file at the right location
    # and the response validates. If it validates locally, submit
    # it to the ACME server.
    try:
        ok = resp.simple_verify(chall, domain, account.public_key())
    except:
        # invalid JSON data yields untrapped errors
        ok = False

    if ok:
        log("Submitting challenge response at %s." % resp.uri(domain, chall))
        return client.answer_challenge(challg_body, resp)

    else:
        log("Validation file is not present.")
        raise NeedToInstallFile(
            resp.uri(domain, chall),
            resp.gen_validation(chall, account).json_dumps(),
            resp.CONTENT_TYPE,
        )


def generate_csr_pyca(domains, key):
    # Generates a CSR and returns a pyca/cryptography CSR object.
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains[1:]]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())
    return csr


def generate_csr(domains, key):
    # Generates a CSR and returns a OpenSSL.crypto.X509Req object.
    from cryptography.hazmat.primitives import serialization
    csr = generate_csr_pyca(domains, key)
    csr = csr.public_bytes(serialization.Encoding.PEM)  # put into PEM format (bytes)

    # Convert the CSR in PEM format to an OpenSSL.crypto.X509Req object.
    import OpenSSL.crypto
    csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    return csr


if __name__ == "__main__":
    main()
