# -*- coding: utf-8 -*-

# Note to self: To upload a new version to PyPI, run:
# python setup.py sdist upload

from setuptools import setup, find_packages

setup(
    name='free_tls_certificates',
    version='0.1.4',
    author=u'Joshua Tauberer',
    author_email=u'jt@occams.info',
    packages = find_packages(),
    url='https://github.com/mail-in-a-box/free_tls_certificates',
    license='CC0 (copyright waived)',
    description='A simple client/tool for Let\'s Encrypt or any ACME server that issues SSL certificates.',
    long_description=open("README.rst").read(),
    keywords="tls ssl certificate acme letsencrypt",
    install_requires=open("requirements.txt").read().split("\n"),
    entry_points={
        'console_scripts': [
            'free_tls_certificate = free_tls_certificates.driver:main',
        ]
    }
)
