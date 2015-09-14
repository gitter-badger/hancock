import os
import ssl
import pefile
import logging
import argparse

import base64
import requests
import subprocess

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from contextlib import contextmanager
from tempfile import NamedTemporaryFile


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('pe_path', help='Path to file or directory of files to analyze')
    parser.add_argument('root_path', help='Path to file or directory of root files')
    return parser.parse_args()


def is_valid(cert, trusted_certs):
    """
    Attempts to validate a given certificate against a list of known root certificates
    :param cert: PEM
    :param trusted_certs: list(PEM)
    :return: bool
    """
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, str(cert))

    # Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()

        # Assuming the certificates are in PEM format in a trusted_certs list
        for _cert in trusted_certs:
            store.add_cert(_cert)

        store_ctx = crypto.X509StoreContext(store, certificate)

        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()

        return True

    except Exception as e:
        logging.exception(e)
        return False


def extract_cert(pe):
    """
    Attempt to extract a der certificate from a PE binary
    :param pe:
    :return:
    """
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    # If theres no cert, then were all done!
    if address == 0:
        logging.info("No certificate found!")
        return
    # Extract the certificate (in DER format)
    return pe.write()[address + 8:]


def verify_binary(path, trusted_certs):
    """
    Verifies a certificate, includes revocation checks and trust chain
    :param path:
    :param trusted_certs:
    :return:
    """
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        logging.warning('%s: %s', e, path)
        return

    cert = extract_cert(pe)

    if not cert:
        logging.debug('No certificate found: %s', path)
        return

    if is_valid(cert, trusted_certs):
        return True
    return False


def convert_to_pem(der):
    """
    Converts DER to PEM
    :param der:
    :return:
    """
    decoded = base64.b64decode(der)
    return ssl.DER_cert_to_PEM_cert(decoded)


@contextmanager
def mktempfile():
    with NamedTemporaryFile(delete=False) as f:
        name = f.name

    try:
        yield name
    finally:
        os.unlink(name)


def ocsp_verify(cert_path, issuer_chain_path):
    """
    Attempts to verify a certificate via OCSP. OCSP is a more modern version
    of CRL in that it will query the OCSP URI in order to determine if the
    certificate as been revoked
    :param cert_path:
    :param issuer_chain_path:
    :return bool: True if certificate is valid, False otherwise
    """
    command = ['openssl', 'x509', '-noout', '-ocsp_uri', '-in', cert_path]
    p1 = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url, err = p1.communicate()

    p2 = subprocess.Popen(['openssl', 'ocsp', '-issuer', issuer_chain_path,
                           '-cert', cert_path, "-url", url.strip()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    message, err = p2.communicate()
    if 'error' in message or 'Error' in message:
        raise Exception("Got error when parsing OCSP url")

    elif 'revoked' in message:
        return

    elif 'good' not in message:
        raise Exception("Did not receive a valid response")

    return True


def crl_verify(cert_path):
    """
    Attempts to verify a certificate using CRL.
    :param cert_path:
    :return: True if certificate is valid, False otherwise
    :raise Exception: If certificate does not have CRL
    """
    with open(cert_path, 'rt') as c:
        cert = x509.load_pem_x509_certificate(c.read(), default_backend())

    distribution_points = cert.extensions.get_extension_for_oid(x509.OID_CRL_DISTRIBUTION_POINTS).value
    for p in distribution_points:
        point = p.full_name[0].value
        response = requests.get(point)
        crl = crypto.load_crl(crypto.FILETYPE_ASN1, response.content)  # TODO this should be switched to cryptography when support exists
        revoked = crl.get_revoked()
        for r in revoked:
            if cert.serial == r.get_serial():
                return
    return True


def verify(cert_path, issuer_chain_path):
    """
    Verify a certificate using OCSP and CRL
    :param cert_path:
    :param issuer_chain_path:
    :return: True if valid, False otherwise
    """
    # OCSP is our main source of truth, in a lot of cases CRLs
    # have been deprecated and are no longer updated
    try:
        return ocsp_verify(cert_path, issuer_chain_path)
    except Exception as e:

        logging.debug("Could not use OCSP: {0}".format(e))
        try:
            return crl_verify(cert_path)
        except Exception as e:
            logging.debug("Could not use CRL: {0}".format(e))
            raise Exception("Failed to verify")
        raise Exception("Failed to verify")


def verify_string(cert_string, issuer_string):
    """
    Verify a certificate given only it's string value
    :param cert_string:
    :param issuer_string:
    :return: True if valid, False otherwise
    """
    with mktempfile() as cert_tmp:
        with open(cert_tmp, 'w') as f:
            f.write(cert_string)
        with mktempfile() as issuer_tmp:
            with open(issuer_tmp, 'w') as f:
                f.write(issuer_string)
            status = verify(cert_tmp, issuer_tmp)
    return status


if __name__ == '__main__':
    args = parse_args()

    pe_path = os.path.abspath(args.path)
    root_path = os.path.abspath(args.path)

    # gather binaries
    binaries = []
    roots = []
    if os.path.isdir(pe_path):
        for f in os.listdir(root_path):
            if os.path.isfile(os.path.join(root_path, f)):
                binaries.append(os.path.join(root_path, f))
            if f.startswith('.'):
                continue

    # gather roots
    elif os.path.isdir(root_path):
        for f in os.listdir(root_path):
            if os.path.isfile(os.path.join(root_path, f)):
                roots.append(os.path.join(root_path, f))
            if f.startswith('.'):
                continue

    for b in binaries:
        logging.info("{0} is {1}".format(b, verify_binary(b, roots)))
