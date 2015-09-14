import os
import pefile
import logging
import argparse


def is_valid(cert):
    print len(cert)


def extract_cert(pe):
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    # If theres no cert, then were all done!
    if address == 0:
        return
    # Extract the certificate (in DER format)
    return pe.write()[address + 8:]


def verify_certificate(path):
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        logging.warning('%s: %s', e, path)
        return

    cert = extract_cert(pe)

    if not cert:
        logging.debug('No certificate found: %s', path)
        return

    if is_valid(cert):
        return True
    return False


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='Path to file or directory of files to analyze')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    path = os.path.abspath(args.path)

    # Handle case where a single file is specificed
    if not os.path.isdir(path):
        verify_certificate(path)
        exit()

    # Handle case where a directory of files is specified
    for f in os.listdir(path):
        if not os.path.isfile(os.path.join(path, f)):
            continue
        if f.startswith('.'):
            continue
        verify_certificate(os.path.join(path, f))
