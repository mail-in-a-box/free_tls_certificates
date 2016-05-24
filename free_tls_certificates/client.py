# Get SSL certificates from Let's Encrypt (letsencrypt.org).
# ----------------------------------------------------------

import sys
import os.path
import json
import datetime
import time

import acme.client
import acme.messages
import acme.challenges

import OpenSSL.crypto

import idna


# General constants.
LETSENCRYPT_SERVER = "https://acme-v01.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_SERVER = "https://acme-staging.api.letsencrypt.org/directory"
ACCOUNT_KEY_SIZE = 2048
EXPIRY_BUFFER_TIME = 60 * 60 * 24 * 2  # two days


# This is a single-use class/object that is used as a flag.
class APPEND_CHAIN:
    pass
APPEND_CHAIN = APPEND_CHAIN()


class DomainValidationMethod(object):
    pass


class HTTPValidation(DomainValidationMethod):
    def __init__(self, port=None, verify_first=True):
        self.port = port # allows override for testing client-side validation
        self.verify_first = verify_first # allows override to skip client-side validation

    def __str__(self):
        return "HTTP Validation"

def issue_certificate(
        domains, account_cache_directory,
        agree_to_tos_url=None, 
        validation_method=HTTPValidation(),
        certificate_file=None,
        certificate_chain_file=APPEND_CHAIN,
        private_key=None, private_key_file=None, csr=None,
        self_signed=None,
        acme_server=LETSENCRYPT_SERVER,
        logger=lambda s : None,
        ):

    # Make sure all domains are IDNA-encoded Py2 unicode/Py 3 str instances.
    # (Note that the IDNA library does not handle wildcards, but neither does ACME yet.)
    domains = [to_idna(domain) for domain in domains]

    if not self_signed:
        # Validate domain ownership with Let's Encrypt. (Skip if generating a
        # self-signed certificate.)
        (client, challenges) = validate_domain_ownership(domains, account_cache_directory,
            agree_to_tos_url, validation_method, acme_server, logger)

    # Domains are now validated. Generate a private key, CSR, and certificate.

    # Load or generate a private key.
    (private_key, private_key_pem) = generate_private_key(private_key, private_key_file, logger)

    if not self_signed:
        # Load or generate a certificate signing request.
        (csr, csr_pem) = parse_or_generate_csr(domains, csr, private_key, logger)

        # Issue a certificate.
        (cert_pem, chain) = request_certificate_issuance(client, challenges, csr, logger)
    else:
        # Generate a self-signed certificate.
        (cert_pem, chain) = issue_self_signed_certificate(domains, private_key, logger)

    # Save everything.
    save_files(certificate_file, cert_pem, certificate_chain_file, chain, private_key_file, private_key_pem, logger)

    # Return what we have.
    return {
        "private_key": private_key_pem,
        "cert": cert_pem,
        "chain": chain,
    }


def validate_domain_ownership(
        domains, account_cache_directory,
        agree_to_tos_url,
        validation_method,
        acme_server,
        logger,
        ):

    # Where will we store our account cache?
    account_key_file = os.path.join(account_cache_directory, 'account.pem')
    registration_file = os.path.join(account_cache_directory, 'registration.json')
    challenges_file = os.path.join(account_cache_directory, 'challenges.json')

    # Create the ACME client, making a new account & registration
    # if not set up yet.
    (client, regr, account) = create_client(
        account_key_file,
        registration_file,
        logger,
        agree_to_tos_url=agree_to_tos_url,
        acme_server=acme_server)

    # Submit domain validation.
    challgs = []
    need_actions = []
    wait_until_when = None
    for domain in domains:
        try:
            # Try this domain's validation.
            challg = submit_domain_validation(client, regr, account, challenges_file, domain, validation_method, logger)
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

    return (client, challgs)


def generate_private_key(private_key, private_key_file, logger):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Read the private key in PEM format if private_key_file is not None and it
    # specifies a file that exists.
    if private_key_file and os.path.exists(private_key_file):
        # Read private key from file.
        with open(private_key_file, "rb") as f:
            private_key = f.read()

    if private_key is None:
        # Generate a new private key if not given to us.
        logger("Generating a new private key.")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

    elif isinstance(private_key, bytes):
        # Deserialize the key if given to us as a bytes string in PEM format.
        private_key_pem = private_key
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())

    elif not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("private_key must be None, a bytes instance containing a private key in PEM format, or a cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey instance (it is a %s)." % type(private_key))

    return (private_key, private_key_pem)


def parse_or_generate_csr(domains, csr, private_key, logger):
    # Create a CSR, if we don't have one already.
    if csr is None:
        logger("Generating a new certificate signing request.")
        (csr_pem, csr) = generate_csr(domains, private_key)

    # Use the provided CSR from a bytes string.
    elif isinstance(csr, bytes):
        # TODO: Validate that the CSR specifies exactly the
        # same domains as the domains array? Let's Encrypt
        # will of course also check this for us.
        csr_pem = csr
        csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)

    else:
        raise ValueError("csr must be None or a bytes instance containing a certificate signing request in PEM format (it is a %s)." % type(csr))

    return (csr, csr_pem)


def request_certificate_issuance(client, challgs, csr, logger):
    # Convert the OpenSSL.crypto.X509Req to a ComparableX509 expected by request_issuance.
    csr = acme.jose.util.ComparableX509(csr)

    # Request a certificate using the CSR and some number of domain validation challenges.
    logger("Requesting a certificate.")
    try:
        cert_response = client.request_issuance(csr, challgs)
    except acme.messages.Error as e:
        if e.typ == "urn:acme:error:rateLimited":
            raise RateLimited(e.detail)
        raise # unhandled

    # Get the certificate chain.
    chain = client.fetch_chain(cert_response)

    # cert_response.body and chain now hold OpenSSL.crypto.X509 objects.
    # Convert them to PEM format.
    cert_pem = cert_to_pem(cert_response.body)
    chain = list(map(cert_to_pem, chain))

    return (cert_pem, chain)


def cert_to_pem(cert):
    return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)


def save_files(certificate_file, cert_pem, certificate_chain_file, chain, private_key_file, private_key_pem, logger):
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

    if private_key_file and not os.path.exists(private_key_file):
        logger("Writing private key to %s." % private_key_file)
        with open(private_key_file, "wb") as f:
            f.write(private_key_pem)


def to_idna(domain):
    # If the domain is passed as a bytes object (alias for str in Python 2),
    # then assume it is already IDNA encoded and decode as if ASCII and work
    # with unicode (Py 2 unicode/Py 3 str) instances.
    if isinstance(domain, bytes):
        return domain.decode("ascii")

    # IDNA-encode, but get back a unicode instance.
    return idna.encode(domain).decode("ascii")

class AccountDataIsCorrupt(Exception):
    def __init__(self, account_file_path):
        self.account_file_path = account_file_path


class NeedToAgreeToTOS(Exception):
    def __init__(self, url):
        self.url = url


class InvalidDomainName(Exception):
    def __init__(self, domain_name, error_message):
        self.domain_name = domain_name
        self.error_message = error_message
    def __str__(self):
        return "'%s' is not a domain name that the ACME server can issue a certificate for (%s)" % (
            self.domain_name, self.error_message)


class NoChallengeMethodsSupported(Exception):
    pass


class ChallengeFailed(Exception):
    def __init__(self, validation_method, domain, message, challenge_uri):
        self.validation_method = validation_method
        self.domain = domain
        self.message = message
        self.challenge_uri = challenge_uri
    def __str__(self):
        return "The %s challenge for %s failed: %s." % (self.validation_method, self.domain, self.message)


class ChallengesUnknownStatus(Exception):
    pass


class WaitABit(Exception):
    def __init__(self, until_when):
        self.until_when = until_when


class NeedToInstallFile(Exception):
    def __init__(self, url, contents, file_name):
        self.url = url
        self.contents = contents
        self.file_name = file_name


class NeedToTakeAction(Exception):
    def __init__(self, actions):
        self.actions = actions


class RateLimited(Exception):
    pass


# Set up the ACME client object by loading/creating an account key
# and registering or validating an existing registration.
def create_client(account_key_file, registration_file, log, agree_to_tos_url=None, acme_server=None):
    # Get or generate the Let's Encrypt account key.
    key = load_or_generate_private_key(account_key_file, log)

    # Create the client.
    client = acme.client.Client(acme_server, key)

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

    elif not os.path.exists(os.path.dirname(keyfile)):
        # Directory for storage does not exist.
        raise ValueError("The path %s does not exist." % os.path.dirname(keyfile))

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
        try:
            regr = client.query_registration(regr)
        except acme.messages.Error as e:
            if e.typ == "urn:acme:error:unauthorized":
                # There is a problem accessing our own account. This probably
                # means the stored registration information is not valid.
                raise AccountDataIsCorrupt(storage)
            raise

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


def submit_domain_validation(client, regr, account, challenges_file, domain, validation_method, log):
    # Get challenges for the domain.
    challg1, resp = get_challenges(client, regr, domain, challenges_file, log)
    challg = challg1.body

    # If this challenge was just issued, we may not have a resp object yet
    # but may still need to raise a WaitABit exception.
    if resp:
        wait_until = client.retry_after(resp, default=60)
    else:
        wait_until = datetime.datetime.now() + datetime.timedelta(seconds=15)

    # The authorization object as a whole has a status.

    if challg.status.name == "valid":
        # This is already valid. Return it immediately.
        log("The challenges for %s have been accepted." % domain)
        return challg1

    elif challg.status.name == "invalid":
        # Challenge was rejected. The ACME server requested the
        # HTTP validation resource but got a 404, for instance.
        message = '; '.join(c.error.detail for c in challg.challenges if c.status.name == "invalid")
        log("The %s challenge for %s failed: %s." % (validation_method, domain, message))
        raise ChallengeFailed(validation_method, domain, message, challg1.uri)

    elif challg.status.name not in ("pending", "processing"):
        # We can only respond to a challenge when its status is
        # pending. What do we do in the remaining case of "unknown"
        # status? ("revoked" is filtered out by get_challenges ---
        # we just request a new challenge in that case.)
        raise ChallengesUnknownStatus(challg.status.name)

    # Look for a challenge combination that we can fulfill.

    for combination in challg.combinations:
        if len(combination) == 1:
            chg = challg.challenges[combination[0]]
            if isinstance(chg.chall, acme.challenges.HTTP01) and isinstance(validation_method, HTTPValidation):
                # The particular challenge within the big authorization object also
                # has a status. I'm not sure what the rules are for when the
                # statuses can be different.
                if chg.status.name == "processing":
                    # The challenge has been submitted and we must wait before proceeding,
                    # which is the next step after the for loop.
                    break

                elif chg.status.name == "valid":
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

                # Submit the HTTP validation challenge, raising NeedToInstallFile if
                # the conditions are not yet met.
                chg = answer_challenge_http(
                    domain,
                    chg.chall,
                    validation_method,
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
        raise NoChallengeMethodsSupported("No supported challenge methods were offered for %s." % domain)

    # On success, or in other cases, wait.
    raise WaitABit(wait_until)


def get_challenges(client, regr, domain, challenges_file, log):
    # Load the cache of challenges.
    challenges = load_challenges_file(challenges_file)

    # If challenges exist for this domain, reuse it.
    # We've already dropped expired and revoked challenges, so we don't have
    # to check that here.
    for i, challg in enumerate(challenges):
        if challg.body.identifier.typ.name == "dns" and challg.body.identifier.value == domain:
            log("Reusing existing challenges for %s." % domain)

            # Refresh the record because it may have been updated with validated challenges.
            try:
                challg, resp = client.poll(challg)
            except acme.messages.Error as e:
                if e.typ in ("urn:acme:error:unauthorized", "urn:acme:error:malformed"):
                    # There is a problem accessing our own account. This probably
                    # means the stored registration information is not valid.
                    raise AccountDataIsCorrupt(challenges_file)
                raise

            # Check that the refreshed record is not expired/revoked. Those
            # aren't helpful. It might be "invalid", meaning a challenge
            # failed. We'll percolate up an invalid challenge so the user
            # gets a ChallengeFailed exception, but we'll also drop it from
            # the cache so that it doesn't prevent further attempts to get
            # a certificate from proceeding.
            if is_still_valid_challenge(challg):
                if challg.body.status.name != "invalid":
                    # Update cache.
                    challenges[i] = challg
                else:
                    # Drop from cache.
                    challenges.pop(i)

                # Stop loop here: Use this challenge.
                break
    else:
        # None found.
        challg = None
        resp = None

    if challg is None:
        # Get new challenges for a domain.
        log("Requesting new challenges for %s." % domain)
        try:
            challg = client.request_domain_challenges(domain, regr.new_authzr_uri)
        except acme.messages.Error as e:
            if e.typ == "urn:acme:error:malformed":
                raise InvalidDomainName(domain, e.detail)
            raise

        # Add into our existing challenges.
        challenges.append(challg)

    # Write a cache of challenges.
    save_challenges_file(challenges, challenges_file)

    # Return the new challenges for this domain, and if we updated it,
    # then the response object so we can know how long to wait before
    # polling again.
    return (challg, resp)


def load_challenges_file(challenges_file):
    # Load any existing challenges we've requested for domains so we
    # can track the challenges we've requested across sessions.
    challenges = []
    if os.path.exists(challenges_file):
        with open(challenges_file) as f:
            challenges = json.load(f)

    # Convert from JSON to ACME objects.
    for i in range(len(challenges)):
        challenges[i] = \
            acme.messages.AuthorizationResource.from_json(challenges[i])

    # Drop any challenges that have expired or have been revoked.
    challenges = [challg for challg in challenges if is_still_valid_challenge(challg)]

    return challenges


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


def save_challenges_file(challenges, challenges_file):
    # Save new set of challenges.
    with open(challenges_file, 'w') as f:
        f.write(json.dumps([c.to_json() for c in challenges], sort_keys=True, indent=4))


def answer_challenge_http(domain, chall, validation_method, client, account, challg_body, log):
    # Create a challenge response object.
    resp = chall.response(account)

    # See if we've already installed the file at the right location
    # and the response validates. If it validates locally, submit
    # it to the ACME server.

    if validation_method.verify_first:
        try:
            # the 'port' argument is for unit testing only
            ok = resp.simple_verify(chall, domain, account.public_key(), port=validation_method.port)
        except:
            # assume any untrapped errors means something failed
            ok = False
    else:
        ok = True

    file_url = chall.uri(domain)

    if ok:
        log("Submitting challenge response file at %s." % file_url)
        return client.answer_challenge(challg_body, resp)

    else:
        log("Validation file is not present --- a file must be installed on the web server.")
        raise NeedToInstallFile(
            file_url,
            chall.validation(account),
            chall.encode("token"), # the filename
        )


def generate_csr_pyca(domains, key):
    # Generates a CSR and returns a pyca/cryptography CSR object.
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    import sys
    if sys.version_info < (3,):
        # In Py2, pyca requires the CN to be a unicode instance.
        domains = [domain.decode("ascii") for domain in domains]

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
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

def issue_self_signed_certificate(domains, private_key, logger):
    # Generates a self-signed certificate.
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from cryptography.x509 import DNSName
    import datetime
    import uuid

    logger("Issuing self-signed certificate.")

    import sys
    if sys.version_info < (3,):
        # In Py2, pyca requires the CN to be a unicode instance.
        domains = [domain.decode("ascii") for domain in domains]

    # https://cryptography.io/en/latest/x509/reference/
    one_day = datetime.timedelta(days=1)
    duration = datetime.timedelta(days=31)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + duration)
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(private_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    if len(domains) > 1:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName(domain) for domain in domains]), critical=False)
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return (cert_to_pem(certificate), []) # no chain
