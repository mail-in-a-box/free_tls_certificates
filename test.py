import unittest

import re
import os
import os.path
import subprocess
import tempfile
import requests.exceptions
import acme.messages

from letsencrypt_simpleclient import client

ACME_SERVER = "http://0.0.0.0:4000/directory"
domains = ["localhost.test-domain.invalid.xyz"]
validation_method = client.SimpleHTTP(5001)

def run():
    # Start a locally running web server that will serve
    # the virtual path '/.well-known/acme-challenge/' from
    # a temporary directory, with the correct content-type
    # header.
    with tempfile.TemporaryDirectory() as tempdir:
        output_dir = os.path.join(tempdir, 'output')
        challenges_dir = os.path.join(tempdir, 'acme-challenges')
        account_dir = os.path.join(tempdir, 'acme-account')
        
        os.mkdir(output_dir)
        os.mkdir(challenges_dir)
        os.mkdir(account_dir)

        httpd = subprocess.Popen(["python3", os.path.join(os.path.abspath(os.path.dirname(__file__)), "test_http_server.py")],
            cwd=challenges_dir)
        try:
            MyTest.output_dir = output_dir
            MyTest.challenges_dir = challenges_dir
            MyTest.account_dir = account_dir

            unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(MyTest))
        finally:
            httpd.terminate()


class MyTest(unittest.TestCase):
    def do_issue(self, domains=domains, **kwargs):
        client.issue_certificate(
            domains,
            self.account_dir,
            validation_method=validation_method,
            certificate_file=os.path.join(self.output_dir, "certificate.crt"),
            certificate_chain_file=os.path.join(self.output_dir, "chain.crt"),
            acme_server=ACME_SERVER,
            **kwargs)

    # This method needs to occur first because the other tests depend on the
    # ACME terms of service being agreed to, so we use two _'s to make it
    # lexicographically first.
    def test__main(self):
        # Call the first time. It raises an exception telling us the
        # URL to the terms of service agreement the user needs to agree to.
        with self.assertRaises(client.NeedToAgreeToTOS) as cm:
            self.do_issue()
        tos_url = cm.exception.url

        # Now agree. But it'll raise an exception telling us we need
        # to make a file available at a certain URL.
        with self.assertRaises(client.NeedToTakeAction) as cm:
            self.do_issue(agree_to_tos_url=tos_url)
        actions = cm.exception.actions

        # It should give us as many actions as domains we asked to verify.
        self.assertEqual(len(actions), len(domains))

        for action in actions:
            # Check that each action is a SimpleHTTP validation file request.
            self.assertIsInstance(action, client.NeedToInstallFile)
            self.assertRegex(action.url, r"http://[^/]+/.well-known/acme-challenge/")
            self.assertEqual(action.content_type, "application/jose+json")
            self.assertRegex(action.contents, r"\{.*\}$")
            self.assertRegex(action.file_name, r"^[A-Za-z0-9_-]{40,50}$")

            # Create the file so we can pass validation. We write it to the
            # directory that our local HTTP server is serving.
            fn = os.path.join(self.challenges_dir, action.file_name)
            with open(fn, 'w') as f:
                f.write(action.contents)

        # Try to get the certificate again, but it'll tell us to wait while
        # the ACME server processes the request.
        validation_method.verify_first = False
        with self.assertRaises(client.WaitABit) as cm:
            self.do_issue()

        # Now actually wait until the certificate is issued.
        while True:
            try:
                # Try to get the certificate again.
                self.do_issue()

                # Success.
                break
            except client.WaitABit:
                import time
                time.sleep(1)
                continue

        # Check that the certificate is valid.
        cert = load_cert_chain(os.path.join(self.output_dir, 'certificate.crt'))
        self.assertEqual(len(cert), 1) # one element in certificate file
        cn, sans = get_certificate_domains(cert[0])
        self.assertEqual(cn, domains[0])
        self.assertEqual(sans - { domains[0] }, set(domains[1:]))

        # Check that the chain is valid.
        chain = load_cert_chain(os.path.join(self.output_dir, 'chain.crt'))
        self.assertEqual(len(chain), 1) # one element in chain
        cn, sans = get_certificate_domains(chain[0])
        self.assertEqual(cn, 'happy hacker fake CA')

        # Check that the certificate is signed by the first element in the chain.
        self.assertEqual(cert[0].issuer, chain[0].subject)

    def test_invalid_domain(self):
        # TOS is already agreed to by main test.
        with self.assertRaises(client.InvalidDomainName) as cm:
            self.do_issue(domains=["test.invalid"])

    def test_challenge_fails(self):
        # Submit a challenge immediately, even though we haven't yet
        # installed a file.
        validation_method.verify_first = False
        with self.assertRaises(client.WaitABit) as cm:
            self.do_issue(domains=["invalid.test-domain.invalid.xyz"])
        
        # Give the Boulder server a chance to evaluate the challenge
        # and go from pending status to invalid status.
        import time
        time.sleep(5)
                
        # Try to issue, but it will fail now.
        with self.assertRaises(client.ChallengeFailed):
            self.do_issue(domains=["invalid.test-domain.invalid.xyz"])

        # And on any future attempts, because the challenge is cached.
        with self.assertRaises(client.ChallengeFailed) as cm:
            self.do_issue(domains=["invalid.test-domain.invalid.xyz"])

        # Clear the challenge from the cache so we get issued a new one.
        client.forget_challenge(cm.exception.challenge_uri, self.account_dir)

        # Get a new challenge. Write the challenge response file.
        validation_method.verify_first = True
        with self.assertRaises(client.NeedToTakeAction) as cm:
            self.do_issue(domains=["invalid.test-domain.invalid.xyz"])
        for action in cm.exception.actions:
            fn = os.path.join(self.challenges_dir, action.file_name)
            with open(fn, 'w') as f:
                f.write(action.contents)

        # Submit and wait.
        validation_method.verify_first = False # it won't resolve so we can't verify
        with self.assertRaises(client.WaitABit) as cm:
            self.do_issue(domains=["invalid.test-domain.invalid.xyz"])

        # Get the certificate.
        while True:
            try:
                # Try to get the certificate again.
                self.do_issue(domains=["invalid.test-domain.invalid.xyz"])
                break
            except client.WaitABit:
                time.sleep(1)
                continue

    def test_invalid_private_key_argument(self):
        # We're already authorized by the main test to issue the certificate.
        with self.assertRaises(ValueError):
            self.do_issue(private_key="my str instance is not a bytes instance")

    def test_invalid_csr_argument(self):
        # We're already authorized by the main test to issue the certificate.
        with self.assertRaises(ValueError):
            self.do_issue(csr="my str instance is not a bytes instance")


def load_cert_chain(pemfile):
    # A certificate .pem file may contain a chain of certificates.
    # Load the file and split them apart.
    re_pem = rb"(-+BEGIN (?:.+)-+[\r\n]+(?:[A-Za-z0-9+/=]{1,64}[\r\n]+)+-+END (?:.+)-+[\r\n]+)"
    with open(pemfile, "rb") as f:
        pem = f.read() + b"\n" # ensure trailing newline
        pemblocks = re.findall(re_pem, pem)
        if len(pemblocks) == 0:
            raise ValueError("File does not contain valid PEM data.")
        return [load_pem(pem) for pem in pemblocks]


def load_pem(pem):
    # Parse a "---BEGIN .... END---" PEM string and return a Python object for it
    # using classes from the cryptography package.
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends import default_backend
    pem_type = re.match(b"-+BEGIN (.*?)-+[\r\n]", pem)
    if pem_type and pem_type.group(1) == b"CERTIFICATE":
        return load_pem_x509_certificate(pem, default_backend())
    raise ValueError("Unsupported PEM object type.")


def get_certificate_domains(cert):
    from cryptography.x509 import DNSName, ExtensionNotFound, OID_COMMON_NAME, OID_SUBJECT_ALTERNATIVE_NAME

    cn = None
    sans = set()

    try:
        cn = cert.subject.get_attributes_for_oid(OID_COMMON_NAME)[0].value
    except IndexError:
        pass

    try:
        sans = set(cert.extensions.get_extension_for_oid(OID_SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(DNSName))
    except ExtensionNotFound:
        pass

    return (cn, sans)


if __name__ == "__main__":
    run()
