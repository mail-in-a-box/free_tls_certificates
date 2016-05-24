import re

re_pem = b"(-+BEGIN (?:.+)-+[\\r\\n]+(?:[A-Za-z0-9+/=]{1,64}[\\r\\n]+)+-+END (?:.+)-+[\\r\\n]+)"
re_pem_type = b"-+BEGIN (.*?)-+[\\r\\n]"

def load_certificate(fn, with_chain=False):
    # Read the PEM file in binary format.
    with open(fn, "rb") as f:
        pem = f.read()

    # A PEM file may contain multiple BEGIN...END blocks of PEM data. Certificates
    # often store a certificate chain this way --- with the actual certificate the
    # first one.
    pem += b"\n" # ensure trailing newline
    pemblocks = re.findall(re_pem, pem)
    if len(pemblocks) == 0:
        raise ValueError("File does not contain any valid PEM data.")
    
    pems = [parse_pem_block(pem) for pem in pemblocks]
    if with_chain:
        return pems
    else:
        return pems[0]

def parse_pem_block(pem):
    # What type of PEM block is this?
    pem_type = re.match(re_pem_type, pem)
    if not pem_type or pem_type.group(1) != b"CERTIFICATE":
        raise ValueError("File does not contain a valid PEM-formatted TLS (SSL) certificate.")
    
    # Parse and return a cryptography.x509.Certificate instance.
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends import default_backend
    return load_pem_x509_certificate(pem, default_backend())


def get_certificate_cn(cert):
    # Gets the certificate's common name.
    from cryptography.x509 import OID_COMMON_NAME
    return cert.subject.get_attributes_for_oid(OID_COMMON_NAME)[0].value

def get_certificate_domains(cert):
    # Gets the common name and the subject alternative names in the
    # certificate. Returns a list of names, the CN first, all IDNA
    # encoded (i.e. in ASCII).
    from cryptography.x509 import DNSName, ExtensionNotFound, OID_SUBJECT_ALTERNATIVE_NAME
    import idna

    ret = []

    # Get the Subject Common Name (CN) (in IDNA ASCII).
    try:
        ret.append(get_certificate_cn(cert))
    except IndexError:
        # No common name?
        pass

    # Get Subject Alternative Names. The cryptography library handily IDNA-decodes
    # the names for us. We must encode back to ASCII, but wildcard certificates can't pass through
    # IDNA encoding/decoding so we must special-case. See https://github.com/pyca/cryptography/pull/2071.
    def idna_decode_dns_name(dns_name):
        if dns_name.startswith("*."):
            return "*." + idna.encode(dns_name[2:]).decode('ascii')
        else:
            return idna.encode(dns_name).decode('ascii')

    try:
        sans = cert.extensions.get_extension_for_oid(OID_SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(DNSName)
        for san in sans:
            ret.append(idna_decode_dns_name(san))
    except ExtensionNotFound:
        pass

    return ret