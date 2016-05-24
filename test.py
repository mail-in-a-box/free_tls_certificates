# -*- coding: utf8 -*-
import unittest

import sys
import re
import os
import os.path
import time
import multiprocessing
import tempfile
import shutil
import requests.exceptions
import acme.messages

from free_tls_certificates import client
from free_tls_certificates.utils import get_certificate_domains

ACME_SERVER = "http://0.0.0.0:4000/directory"
domains = ["x1.le.wtf"] # le.wtf is coded to have a high rate limit in the default Boulder test files

if sys.version_info < (3,):
    unicode_string = unicode("my unicode instance is not a bytes instance")
else:
    unicode_string = "my str instance is not a bytes instance"

def run():
    # Start a locally running web server that will serve
    # the virtual path '/.well-known/acme-challenge/' from
    # a temporary directory, with the correct content-type
    # header.
    tempdir = tempfile.mkdtemp()
    try:
        # Where should we store things?

        output_dir = os.path.join(tempdir, 'output')
        challenges_dir = os.path.join(tempdir, 'acme-challenges')
        account_dir = os.path.join(tempdir, 'acme-account')

        os.mkdir(output_dir)
        os.mkdir(challenges_dir)
        os.mkdir(account_dir)

        # Start the domain validation server.

        httpd = create_dv_server(challenges_dir)
        httpd_proc = multiprocessing.Process(target=lambda : httpd.serve_forever())
        httpd_proc.start()
        try:

            # Start the tests.

            MyTest.output_dir = output_dir
            MyTest.challenges_dir = challenges_dir
            MyTest.account_dir = account_dir

            unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(MyTest))

        finally:
            httpd_proc.terminate()
    finally:
        shutil.rmtree(tempdir)

class MyTest(unittest.TestCase):
    def do_issue(self, domains=domains, validation_method=client.HTTPValidation(port=5002), **kwargs):
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
            # Check that each action is a HTTP validation file request.
            self.assertIsInstance(action, client.NeedToInstallFile)
            self.assertTrue(re.match(r"http://[^/]+/.well-known/acme-challenge/", action.url))
            self.assertTrue(re.match(r"^[A-Za-z0-9\._-]{60,100}$", action.contents))
            self.assertTrue(re.match(r"^[A-Za-z0-9_-]{40,50}$", action.file_name))

            # Create the file so we can pass validation. We write it to the
            # directory that our local HTTP server is serving.
            fn = os.path.join(self.challenges_dir, action.file_name)
            with open(fn, 'w') as f:
                f.write(action.contents)

        # Try to get the certificate again, but it'll tell us to wait while
        # the ACME server processes the request.
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
                time.sleep(1)
                continue

        # Check that the certificate is valid.
        cert = load_cert_chain(os.path.join(self.output_dir, 'certificate.crt'))
        self.assertEqual(len(cert), 1) # one element in certificate file
        cert_domains = get_certificate_domains(cert[0])
        self.assertEqual(cert_domains[0], domains[0])
        self.assertEqual(set(cert_domains), set(domains))

        # Check that the chain is valid.
        chain = load_cert_chain(os.path.join(self.output_dir, 'chain.crt'))
        self.assertEqual(len(chain), 1) # one element in chain
        chain_names = get_certificate_domains(chain[0])
        self.assertEqual(chain_names[0], 'happy hacker fake CA')

        # Check that the certificate is signed by the first element in the chain.
        self.assertEqual(cert[0].issuer, chain[0].subject)

    def test_i8n_domain(self):
        domains = [u"tëst.le.wtf", u"tëst2.le.wtf"]

        # The main test already agreed to the TOS...

        # Get the challenge details.
        with self.assertRaises(client.InvalidDomainName) as cm:
            self.do_issue(domains=domains)

        # LE doesn't yet support internationalized domains, but we should get
        # back this error telling us.
        self.assertIn("Internationalized domain names", str(cm.exception))

    def test_invalid_domain(self):
        # TOS is already agreed to by main test.
        with self.assertRaises(client.InvalidDomainName) as cm:
            self.do_issue(domains=["test.invalid"])

    def test_challenge_fails(self):
        # Submit a challenge immediately, even though we haven't yet
        # installed a file.
        vm = validation_method=client.HTTPValidation(port=5002, verify_first=False)
        with self.assertRaises(client.WaitABit) as cm:
            self.do_issue(domains=["fail.le.wtf"], validation_method=vm)
        
        # Give the Boulder server a chance to evaluate the challenge
        # and go from pending status to invalid status.
        time.sleep(5)
                
        # Try to issue, but it will fail now.
        with self.assertRaises(client.ChallengeFailed):
            self.do_issue(domains=["fail.le.wtf"], validation_method=vm)

        # The failed challenge is removed from the cache so that further
        # attempts from scratch aren't blocked.

        # Get a new challenge. Write the challenge response file.
        with self.assertRaises(client.NeedToTakeAction) as cm:
            self.do_issue(domains=["fail.le.wtf"])
        for action in cm.exception.actions:
            fn = os.path.join(self.challenges_dir, action.file_name)
            with open(fn, 'w') as f:
                f.write(action.contents)

        # Submit and wait.
        with self.assertRaises(client.WaitABit) as cm:
            self.do_issue(domains=["fail.le.wtf"], validation_method=vm)

        # Get the certificate.
        while True:
            try:
                # Try to get the certificate again.
                self.do_issue(domains=["fail.le.wtf"])
                break
            except client.WaitABit:
                time.sleep(1)
                continue

    def test_invalid_private_key_argument(self):
        # We're already authorized by the main test to issue the certificate.
        with self.assertRaises(ValueError):
            self.do_issue(private_key=unicode_string)

    def test_invalid_csr_argument(self):
        # We're already authorized by the main test to issue the certificate.
        with self.assertRaises(ValueError):
            self.do_issue(csr=unicode_string)

    def test_self_signed(self):
        self.do_issue(domains=["selfsigned.le.wtf", "www.selfsigned.le.wtf"], self_signed=True)

        from free_tls_certificates.utils import load_certificate, get_certificate_cn, get_certificate_domains
        cert = load_certificate(os.path.join(self.output_dir, "certificate.crt"))
        self.assertEqual(cert.issuer, cert.subject)
        self.assertEqual(get_certificate_cn(cert), "selfsigned.le.wtf")
        self.assertEqual(set(get_certificate_domains(cert)), set(["selfsigned.le.wtf", "www.selfsigned.le.wtf"]))

    def test_driver(self, self_signed=False):
        # Run the driver program to issue the certificate.

        # Make sure no certificate file already exists.
        cert_fn = os.path.join(self.output_dir, 'driver_certificate.crt')
        if os.path.exists(cert_fn):
            os.unlink(cert_fn)

        # Run the driver.
        import subprocess
        def execute_driver_app():
            if not self_signed:
                args = ["--server", ACME_SERVER]
            else:
                args = ["--self-signed"]
            subprocess.check_call(
                [
                    sys.executable, "free_tls_certificates/driver.py",
                ]
                + args
                + domains
                + [
                    os.path.join(self.output_dir, 'driver_private.key'),
                    os.path.join(self.output_dir, 'driver_certificate.crt'),
                    self.challenges_dir,
                    self.account_dir,
                ], env={ "PYTHONPATH": ".:" + ":".join(sys.path) })
        execute_driver_app()

        # Check that the private key was written.
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, 'driver_private.key')))

        # Check that the certificate is valid.
        cert = load_cert_chain(cert_fn)
        if not self_signed:
            self.assertEqual(len(cert), 2) # two elements in chain
        else:
            self.assertEqual(len(cert), 1) # no chain, just the cert
        cert_domains = get_certificate_domains(cert[0])
        self.assertEqual(cert_domains[0], domains[0])
        self.assertEqual(set(cert_domains), set(domains))

        if not self_signed:
            # Check that the chain is valid.
            chain_names = get_certificate_domains(cert[1])
            self.assertEqual(chain_names[0], 'happy hacker fake CA')

            # Check that the certificate is signed by the first element in the chain.
            self.assertEqual(cert[0].issuer, cert[1].subject)
        else:
            # Check that the certificate is actually self-signed.
            from free_tls_certificates.utils import load_certificate
            cert = load_certificate(cert_fn)
            self.assertEqual(cert.issuer, cert.subject)

        # Run the driver again --- this time it should say that the certificate
        # exists and is valid and exits with a return code of 3.
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            execute_driver_app()
        self.assertEqual(cm.exception.returncode, 3)

    def test_driver_selfsigned(self):
        self.test_driver(self_signed=True)

def load_cert_chain(pemfile):
    from free_tls_certificates.utils import load_certificate
    return load_certificate(pemfile, with_chain=True)

def create_dv_server(challenges_dir):
    # We need a simple HTTP server to respond to
    # Boulder's domain validation requests.

    import os.path

    root_path = "/.well-known/acme-challenge/"
    def translate_path(path):
        if path.startswith(root_path):
            # Strip the well-known prefix so we serve only
            # that directory.
            path = path[len(root_path):]
        fn = os.path.join(challenges_dir, path)
        return fn

    if sys.version_info < (3,):
        from BaseHTTPServer import BaseHTTPRequestHandler
        from SocketServer import TCPServer as HTTPServer
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fn = translate_path(self.path)
                if os.path.exists(fn):
                    self.send_response(200)
                    self.end_headers()
                    with open(fn) as f:
                        self.wfile.write(f.read())
                else:
                    self.send_error(404)
    else:
        from http.server import SimpleHTTPRequestHandler
        from http.server import HTTPServer
        class Handler(SimpleHTTPRequestHandler):
            def translate_path(self, path):
                return translate_path(path)

    return HTTPServer(('', 5002), Handler)


if __name__ == "__main__":
    run()
