from functools import cached_property

import logging
import base64
import hashlib
import rsa
import rsa.pkcs1
import dkim_signature

from email.message import EmailMessage
from canonicalization import relaxed, simple
from utility import get_public_key

logger = logging.getLogger(__name__)

# a module for validating the DKIM

# see - https://www.ietf.org/rfc/rfc6376.txt
class DKIM_Validator:
    def __init__(self, headers: EmailMessage, body: bytes):
        assert(isinstance(headers, EmailMessage))
        self.headers_ = headers
        # the body must be a set of bytes
        assert(isinstance(body, bytes))
        self.message_ = body
        # 6.1 - Extract signatures from the message
        self.dkim_ = dkim_signature.from_email_message(headers)
    
    # Returns the canonicalized body
    @cached_property
    def canonicalized_body(self):
        # assemble as a byte array
        algo = self.dkim_.body_algo
        if algo == 'simple':
            message_body = simple.apply_body(self.message_)
        elif algo == 'relaxed':
            message_body = relaxed.apply_body(self.message_)
        else:
            raise ValueError('unknown canonicalization algo')

        length = self.dkim_.body_length
        if length is None:
            return message_body
        
        # return the subpart of the canonicalized body
        return message_body[0:length]

    @cached_property
    def public_key(self):
        assert(self.dkim_.key_type == 'rsa')
        # Retrieves the public key from DNS
        public_key = get_public_key(self.dkim_.selector, self.dkim_.domain)
        logger.debug(f'retrieving public_key => {public_key}')
        return public_key

    @cached_property
    def hash_func(self):
        # Returns the hash function associated with the named hash algo
        # rsa-256 and rsa-sha1 supported
        if self.dkim_.hash_algo == 'rsa-sha256':
            logger.debug('hash_func: selecting sha256')
            return lambda x: hashlib.sha256(x).digest()
        elif self.dkim_.hash_algo == 'rsa-sha1':
            logger.debug('hash_func: selecting sha1')
            return lambda x: hashlib.sha1(x).digest()
        else:
            raise ValueError('invalid hashing function')

    @cached_property
    def body_hash(self):
        # verify the message body hash
        message_body = self.canonicalized_body
        message_hash = self.hash_func(message_body)
        self.body_hash_bytes_ = base64.b64encode(message_hash)
        self.body_hash_ = self.body_hash_bytes_.decode()
        logger.info(f'body_hash[calculated] => {self.body_hash_}')
        return self.body_hash_

    @cached_property
    def header_algo(self):
        algo = self.dkim_.header_algo
        if algo == 'simple':
            return simple.apply_header
        elif algo == 'relaxed':
            return relaxed.apply_header
        else:
            raise ValueError('unknown canonicalization algo')

    @property
    def signed_headers_list(self):
        signed_headers = []
        signed_headers_set = set()
        for header_name in self.dkim_.h_headers:
            header_key = header_name.lower()
            if header_key in signed_headers_set:
                continue

            header_value = self.header_algo(self.headers_[header_name])
            if header_value is None:
                continue

            logger.debug(f'add to signed headers: {header_key}:{header_value}')
            signed_headers_set.add(header_key)
            signed_headers.append(f'{header_key}:{header_value}')

        return signed_headers

    def validate(self):
        # Verify that the hash of the canonicalized message body matches the
        # hash value conveyed in the "bh=" tag.
        logger.info(f'body_hash[received] => {self.dkim_.body_hash}')
        if (self.body_hash != self.dkim_.body_hash):
            logger.warn(f'DKIM signature verification failed: PERMFAIL (body hash did not verify)' )
            raise ValueError('PERMFAIL (body hash did not verify)')

        logger.info(f'Verified that body_hash[calculated] == body_hash[received]')

        # The header fields specified by the "h=" tag, in the order
        # specified in that tag, and canonicalized using the header
        # canonicalization algorithm specified in the "c=" tag.  Each
        # header field MUST be terminated with a single CRLF.
        signed_headers = self.signed_headers_list

        # The DKIM-Signature header field that exists (verifying) or will
        # be inserted (signing) in the message, with the value of the "b="
        # tag (including all surrounding whitespace) deleted (i.e., treated
        # as the empty string), canonicalized using the header
        # canonicalization algorithm specified in the "c=" tag, and without
        # a trailing CRLF.
        signed_headers.append(self.dkim_.encoded_tag_string)
        signed_headers = '\r\n'.join(signed_headers).encode()

        # Using the signature conveyed in the "b=" tag, verify the
        # signature against the header hash using the mechanism appropriate
        # for the public-key algorithm described in the "a=" tag.  If the
        # signature does not validate, the Verifier SHOULD ignore the
        # signature and return PERMFAIL (signature did not verify).
        signature = base64.b64decode(self.dkim_.signature)

        try:
            # Use the public key to verify
            validation_result = rsa.verify(signed_headers, signature, self.public_key)
            logger.debug(f'validation_result = {validation_result}')

            # Otherwise, the signature has correctly verified.
            logger.info('DKIM signature verification succeeded')
        except rsa.pkcs1.VerificationError as e:
            logger.warn(f'DKIM signature verification failed: {repr(e)}' )