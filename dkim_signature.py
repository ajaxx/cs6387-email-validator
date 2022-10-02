from email.message import EmailMessage

import re
import sys

from utility import split_keypair

DEFAULT_QUERY_METHOD = 'dns/txt'

ALLOWED_HASH_ALGOS = ('rsa-sha1', 'rsa-sha256')

class DKIM_Signature():
    def __init__(self, dkim_signature):
        dkim_signature = re.sub(r'\s*\t\s*', ' ', dkim_signature)
        dkim_signature = re.sub(r'\s;\s*', '', dkim_signature)
        dkim_signature = dkim_signature.split(';')

        dkim_tags = [split_keypair(x.lstrip()) for x in dkim_signature for x in x.split(';')]
        self.tags_ = dkim_tags

        dkim_tags = dict(dkim_tags)

        # v= Version (plain-text; REQUIRED).  This tag defines the version of
        #    this specification that applies to the signature record.  It MUST
        #    have the value "1" for implementations compliant with this version
        #    of DKIM.
        self.version = dkim_tags['v']

        self.key_type = dkim_tags.get('k', 'rsa')
        if self.key_type != 'rsa':
            raise ValueError('invalid value for key_type')

        # q= A colon-separated list of query methods used to retrieve the
        #       public key (plain-text; OPTIONAL, default is "dns/txt").  Each
        #       query method is of the form "type[/options]", where the syntax and
        #       semantics of the options depend on the type and specified options.
        #       If there are multiple query mechanisms listed, the choice of query
        #       mechanism MUST NOT change the interpretation of the signature.
        #       Implementations MUST use the recognized query mechanisms in the
        #       order presented.  Unrecognized query mechanisms MUST be ignored.
        self.query = dkim_tags.get('q', DEFAULT_QUERY_METHOD)
        if self.query != DEFAULT_QUERY_METHOD:
            # Currently, the only valid value is "dns/txt", which defines the
            #     DNS TXT resource record (RR) lookup algorithm described elsewhere
            #     in this document.  The only option defined for the "dns" query
            #     type is "txt", which MUST be included.  Verifiers and Signers MUST
            #     support "dns/txt".
            raise ValueError('invalid value for query')

        # a= The algorithm used to generate the signature (plain-text;
        #   REQUIRED).  Verifiers MUST support "rsa-sha1" and "rsa-sha256";
        #   Signers SHOULD sign using "rsa-sha256".  See Section 3.3 for a
        #   description of the algorithms.
        self.hash_algo = dkim_tags['a']
        if self.hash_algo not in ALLOWED_HASH_ALGOS:
            raise ValueError('invalid value for hash algo')

        # bh=  The hash of the canonicalized body part of the message as
        #      limited by the "l=" tag (base64; REQUIRED).  Whitespace is ignored
        #      in this value and MUST be ignored when reassembling the original
        #      signature.  In particular, the signing process can safely insert
        #      FWS in this value in arbitrary places to conform to line-length
        #      limits.  See Section 3.7 for how the body hash is computed.
        self.body_hash = dkim_tags['bh']

        #   l= Body length count (plain-text unsigned decimal integer; OPTIONAL,
        #      default is entire body).  This tag informs the Verifier of the
        #      number of octets in the body of the email after canonicalization
        #      included in the cryptographic hash, starting from 0 immediately
        #      following the CRLF preceding the body.  This value MUST NOT be
        #      larger than the actual number of octets in the canonicalized
        #      message body.
        self.body_length = dkim_tags.get('l')

        #   c= Message canonicalization (plain-text; OPTIONAL, default is
        #      "simple/simple").  This tag informs the Verifier of the type of
        #      canonicalization used to prepare the message for signing.  It
        #      consists of two names separated by a "slash" (%d47) character,
        #      corresponding to the header and body canonicalization algorithms,
        #      respectively.  These algorithms are described in Section 3.4.  If
        #      only one algorithm is named, that algorithm is used for the header
        #      and "simple" is used for the body.  For example, "c=relaxed" is
        #      treated the same as "c=relaxed/simple".
        self.mesg_algo = dkim_tags.get('c', 'simple/simple')
        self.header_algo, self.body_algo = self.mesg_algo.split('/')

        # h= Signed header fields (plain-text, but see description; REQUIRED).
        #       A colon-separated list of header field names that identify the
        #       header fields presented to the signing algorithm.  The field MUST
        #       contain the complete list of header fields in the order presented
        #       to the signing algorithm.  The field MAY contain names of header
        #       fields that do not exist when signed; nonexistent header fields do
        #       not contribute to the signature computation (that is, they are
        #       treated as the null input, including the header field name, the
        #       separating colon, the header field value, and any CRLF
        #       terminator).  The field MAY contain multiple instances of a header
        #       field name, meaning multiple occurrences of the corresponding
        #       header field are included in the header hash.  The field MUST NOT
        #       include the DKIM-Signature header field that is being created or
        #       verified but may include others.  Folding whitespace (FWS) MAY be
        #       included on either side of the colon separator.  Header field
        #       names MUST be compared against actual header field names in a
        #       case-insensitive manner.  This list MUST NOT be empty.  See
        #       Section 5.4 for a discussion of choosing header fields to sign and
        #       Section 5.4.2 for requirements when signing multiple instances of
        #       a single field.
        self.h_headers = dkim_tags['h'].split(':')

        # d= The SDID claiming responsibility for an introduction of a message
        #       into the mail stream (plain-text; REQUIRED).  Hence, the SDID
        #       value is used to form the query for the public key.  The SDID MUST
        #       correspond to a valid DNS name under which the DKIM key record is
        #       published.  The conventions and semantics used by a Signer to
        #       create and use a specific SDID are outside the scope of this
        #       specification, as is any use of those conventions and semantics.
        #       When presented with a signature that does not meet these
        #       requirements, Verifiers MUST consider the signature invalid.
        self.domain = dkim_tags['d']

        #   s= The selector subdividing the namespace for the "d=" (domain) tag
        #      (plain-text; REQUIRED).
        #
        #      Internationalized selector names MUST be encoded as A-labels, as
        #      described in Section 2.3 of [RFC5890].
        self.selector = dkim_tags['s']

        # b= The signature data (base64; REQUIRED).  Whitespace is ignored in
        #    this value and MUST be ignored when reassembling the original
        #    signature.  In particular, the signing process can safely insert
        #    FWS in this value in arbitrary places to conform to line-length
        #    limits.  See "Signer Actions" (Section 5) for how the signature is
        #    computed.
        self.signature = dkim_tags['b']
    
    @property
    def encoded_tags(self):
        for tag in self.tags_:
            if tag[0] == 'b':
                yield 'b='
            else:
                yield f'{tag[0]}={tag[1]}'

    @property
    def encoded_tag_string(self):
        # The DKIM-Signature header field that exists (verifying) or will
        # be inserted (signing) in the message, with the value of the "b="
        # tag (including all surrounding whitespace) deleted (i.e., treated
        # as the empty string), canonicalized using the header
        # canonicalization algorithm specified in the "c=" tag, and without
        # a trailing CRLF.
        joined_tags = '; '.join(self.encoded_tags)
        return f'dkim-signature:{joined_tags}'


def from_email_message(email_message: EmailMessage):
        sig_header = email_message.get('DKIM-Signature')
        if sig_header is None:
            raise KeyError('Missing DKIM-Signature') # might have happened with index
        
        return DKIM_Signature(sig_header)