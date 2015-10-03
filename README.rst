Let's Encrypt Simple Client
===========================

__This is a work in progress.__

This is a simple Python client library for Let's Encrypt, or any ACME server that issues SSL certificates, based on the acme client library.

The purpose of this library is to make it easier to embed Let's Encrypt within server provisioning applications (without resorting to shelling out the letsencrypt command line client).

Prerequisites:

* The Let's Encrypt ``ACME client library``<https://github.com/letsencrypt/letsencrypt/tree/master/acme> and all of its dependencies.

See the module's main method for an example of how to run it.

