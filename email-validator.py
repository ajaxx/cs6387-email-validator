#!/usr/bin/env python

import email
import email.parser
import logging
import logging.handlers
import argparse
import re

from email import policy
from spf_validator import SPF_Validator

from utility import split_keypair

from errors import ParseError

from dkim_validator import DKIM_Validator

def parse_args():
    parser = argparse.ArgumentParser (description = 'Email Validator')
    parser.add_argument ('-d', '--debug', dest='debug', action='store_true', help='Enable debugging logs')
    parser.add_argument ('-f', '--file', dest='filename', action='store', required=True, help='Name of the file to parse')
    return parser.parse_args()

def validate_authentication_results(header):
    auth_results = header.get('authentication-results')
    if auth_results is None:
        print('Authentication results: None')

    auth_results = [split_keypair(x.lstrip()) for x in auth_results for x in x.split(';')]

def get_payload(message_raw: bytes):
    lines = re.split(b"\r?\n", message_raw)
    # skip all of the headers
    for ii in range(0, len(lines)):
        if len(lines[ii]) == 0:
            return b'\r\n'.join(lines[ii+1:])
    
    raise ParseError('Unable to extract payload')

def validate_email():
    args = parse_args()
    
    logging_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level = logging_level)

    with open(args.filename, 'rb') as fh:
        # read the raw message; we need to extract the payload manually because the bytes parser
        # will attempt to turn this into a multipart message (structure) and we have no guarantees
        # that we will get the same payload back.
        message_raw = fh.read()
        # parse the message from the bytes
        message_headers = email.parser.BytesParser(policy = policy.default) \
            .parsebytes(message_raw, headersonly = True)
        # extract the message body
        message_body = get_payload(message_raw)

    # extract the subheader which contains the details we want.  the subheader may have the following keys, it may not
    # arc-message-signature, arc-authentication-results, arc-seal
    # dkim-signature
    # received-spf
    # authentication-results
    #subheader = header['header']

    #validate_authentication_results(subheader)

    # Create an SPF_Validator
    spf_validator = SPF_Validator(message_headers, message_body)
    spf_validator.validate()
    
    # Create a DKIM_Validator
    dkim_validator = DKIM_Validator(message_headers, message_body)
    dkim_validator.validate()

if __name__ == '__main__':
    validate_email()