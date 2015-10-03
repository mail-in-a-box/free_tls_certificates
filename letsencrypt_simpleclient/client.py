# Get SSL certificates from Let's Encrypt (letsencrypt.org).
# ----------------------------------------------------------

import os.path
import json
import datetime
import time
import acme.client
import acme.messages
import acme.challenges
import OpenSSL.crypto

ACME_SERVER = "https://acme-staging.api.letsencrypt.org/directory"
ACCOUNT_KEY_SIZE = 2048
EXPIRY_BUFFER_TIME = 60 * 60 * 24 * 2  # two days


class APPEND_CHAIN:
    pass
APPEND_CHAIN = APPEND_CHAIN()


def simple_logger(s):
    import sys
    print(s, file=sys.stderr)


def issue_certificate(
        domains, account_cache_directory,
        agree_to_tos_url=None, 
        certificate_file=None,
        certificate_chain_file=APPEND_CHAIN,
        private_key=None, csr=None,
        logger=simple_logger,
        ):

    account_key_file = os.path.join(account_cache_directory, 'account.pem')
    registration_file = os.path.join(account_cache_directory, 'registration.json')
    challenges_file = os.path.join(account_cache_directory, 'challenges.json')

    # Create the ACME client, making a new account & registration
    # if not set up yet.
    (client, regr, account) = create_client(account_key_file, registration_file, logger, agree_to_tos_url=agree_to_tos_url)

    # Submit domain validation.
    challgs = []
    need_actions = []
    wait_until_when = None
    for domain in domains:
        try:
            # Try this domain's validation.
            challg = submit_domain_validation(client, regr, account, challenges_file, domain, logger)
            challgs.append(challg)
        except NeedToInstallFile as e:
            # Validation failed because the user needs to take action.
            need_actions.append(e)
        except WaitABit as e:
            # Validation is pending and we're instructed not to poll
            # until after a certain time. Remember the latest such
            # time across the domains.
            wait_until_when = max(wait_until_when or datetime.datetime.min, e.until_when)

    # If any actions need to be taken, raise an exception with those actions.
    if len(need_actions) > 0:
        raise NeedToTakeAction(need_actions)

    # If the validation is in progress and the user needs to wait, indicate that.
    if wait_until_when is not None:
        raise WaitABit(wait_until_when)

    # Domains are now validated. Generate a CSR.

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    if private_key is None:
        # Generate a new private key if not given to us.
        logger("Generating a new private key.")
        from cryptography.hazmat.primitives.asymmetric import rsa
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    elif isinstance(private_key, bytes):
        # Deserialize.
        private_key_pem = private_key
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())

    # Create a CSR, if you don't have one already.
    if csr is None:
        logger("Generating a new certificate signing request.")
        (csr_pem, csr) = generate_csr(domains, private_key)
    elif isinstance(csr, bytes):
        # TODO: Validate that the CSR specifies exactly the
        # same domains as the domains array? Let's Encrypt
        # will of course also check this for us.
        csr_pem = csr
        csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)

    # Request a certificate using the CSR and some number of domain validation challenges.
    logger("Requesting a certificate.")
    cert_response = client.request_issuance(csr, challgs)

    # Get the certificate chain.
    chain = client.fetch_chain(cert_response)

    # cert_response.body and chain now hold OpenSSL.crypto.X509 objects.
    # Convert them to PEM format.
    def cert_to_pem(cert):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    cert_pem = cert_to_pem(cert_response.body)
    chain = list(map(cert_to_pem, chain))

    if certificate_file is not None:
        logger("Writing certificate to %s." % certificate_file)
        with open(certificate_file, 'wb') as f:
            f.write(cert_pem)
            if certificate_chain_file == APPEND_CHAIN:
                for cert in chain:
                    f.write(cert)

    if certificate_chain_file is not None and certificate_chain_file != APPEND_CHAIN \
        and len(chain) > 0:
        logger("Writing certificate chain to %s." % certificate_chain_file)
        with open(certificate_chain_file, 'wb') as f:
            for cert in chain:
                f.write(cert)

    return {
        "private_key": private_key_pem,
        "csr": csr_pem,
        "cert": cert_pem,
        "chain": chain,
    }


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


class NeedToTakeAction(Exception):
    def __init__(self, actions):
        self.actions = actions


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
    challg1, resp = get_challenges(client, regr, domain, challenges_file, log)
    challg = challg1.body

    # The authorization object as a whole has a status.

    if challg.status.name == "valid":
        # This is already valid. Return it immediately.
        log("The challenges for %s have been accepted." % domain)
        return challg1

    elif challg.status.name == "processing":
        # Must wait before proceeding.
         raise WaitABit(client.retry_after(resp, default=60))

    elif challg.status.name != "pending":
        # We can only respond to a challenge when its status is
        # pending. What do we do in the remaining cases?
        # Other statuses are "unknown", "invalid". "revoked" is
        # filtered out by get_challenges --- we just request a
        # new challenge in that case.
        raise ChallengesUnknownStatus(challg.status.name)

    # Look for a challenge combination that we can fulfill.

    for combination in challg.combinations:
        if len(combination) == 1:
            chg = challg.challenges[combination[0]]
            if isinstance(chg.chall, acme.challenges.SimpleHTTP):
                # The particular challenge within the big authorization object also
                # has a status. I'm not sure what the rules are for when the
                # statuses can be different.
                if chg.status.name == "processing":
                    # The challenge has been submitted and we must wait before proceeding,
                    # which is the next step after the for loop.
                    break

                if chg.status.name == "valid":
                    # Looks like we already answered this challenge correctly.
                    # But the overall authorization object is not yet valid,
                    # so instruct the user to wait? That's the next step after
                    # the for loop.
                    break

                elif chg.status.name != "pending":
                    # We can only respond to a challenge when its status is
                    # pending. What do we do in the remaining cases?
                    # Other statuses are "unknown", "invalid" and "revoked".
                    raise ChallengesUnknownStatus(chg.status.name)

                # Submit the SimpleHTTP challenge, raising NeedToInstallFile if
                # the conditions are not yet met.
                chg = answer_challenge_simplehttp(
                    domain,
                    chg.chall,
                    client,
                    account,
                    chg,
                    log)

                # We found a challenge combination we can submit for,
                # and we submitted it. The ChallengeResource probably
                # comes back still pending because it doesn't go THAT
                # fast. The next step after the for loop is to wait.
                break

    else:
        # We were unable to handle any challenge combination.
        raise NoChallengeMethodsSupported()

    # On success, or in other cases, wait.
    raise WaitABit(client.retry_after(resp, default=60))


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

    # Drop any challenges that have expired or have been revoked.
    existing_challenges = list(filter(is_still_valid_challenge, existing_challenges))

    # If challenges exist for this domain, reuse it.
    # We've already dropped expired and revoked challenges, so we don't have
    # to check that here.
    for i, challg in enumerate(existing_challenges):
        if challg.body.identifier.typ.name == "dns" and challg.body.identifier.value == domain:
            log("Reusing existing challenges for %s." % domain)

            # Refresh the record because it may have been updated with validated challenges.
            challg, resp = client.poll(challg)

            # Check that the refreshed record is still valid.
            if is_still_valid_challenge(challg):
                # If so, keep it.
                existing_challenges[i] = challg
                break
    else:
        # None found.
        challg = None
        resp = None

    if challg is None:
        # Get new challenges for a domain.
        log("Requesting new challenges for %s." % domain)
        challg = client.request_domain_challenges(domain, regr.new_authzr_uri)

        # Add into our existing challenges.
        existing_challenges.append(challg)

    # Save new set of challenges.
    with open(challenges_file, 'w') as f:
        f.write(json.dumps([c.to_json() for c in existing_challenges], sort_keys=True, indent=4))

    # Return the new challenges for this domain, and if we updated it,
    # then the response object so we can know how long to wait before
    # polling again.
    return (challg, resp)


def is_still_valid_challenge(challg):
    # Disregard any challenge that has been revoked.
    if challg.body.status.name == "revoked":
        return False
            
    # Make sure the datetime is at least two days into the future,
    # to give us enough time to actually perform the challenge and
    # not have to worry about timezone conversion.
    # This is a really bad date comparison that loses timezone info.
    expires_dt = challg.body.expires
    return (expires_dt.replace(tzinfo=None) - datetime.datetime.utcnow()) > datetime.timedelta(seconds=EXPIRY_BUFFER_TIME)


def answer_challenge_simplehttp(domain, chall, client, account, challg_body, log):
    # Create a challenge response.
    resp = acme.challenges.SimpleHTTPResponse(tls=True)

    # See if we've already installed the file at the right location
    # and the response validates. If it validates locally, submit
    # it to the ACME server.

    # ACME simple HTTP validation over TLS does not require the server's existing
    # SSL certificate to be valid, and in performing the validation check first,
    # before submitting it to the ACME server, the ACME client library will also
    # disable Python's SSL certificate check. That normally issues a warning, but
    # we want to suppress that warning.
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        try:
            ok = resp.simple_verify(chall, domain, account.public_key())
        except:
            # invalid JSON data yields untrapped errors
            ok = False

    if ok:
        log("Submitting challenge response at %s." % resp.uri(domain, chall))
        return client.answer_challenge(challg_body, resp)

    else:
        log("Validation file is not present --- a file must be installed on the web server.")
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
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)  # put into PEM format (bytes)

    # Convert the CSR in PEM format to an OpenSSL.crypto.X509Req object.
    csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)
    return (csr_pem, csr)

