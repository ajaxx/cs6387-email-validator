import re
import logging
import pyparsing as pp
import dns.resolver

from email.message import EmailMessage
from tracemalloc import DomainFilter

from pyparsing import OneOrMore, Word, pyparsing_common
import pyparsing.results

from utility import split_keypair

logger = logging.getLogger(__name__)

# a module for validating the SPF

class SPF_Validator:
    def __init__(self, headers: EmailMessage, body: bytes):
        assert(isinstance(headers, EmailMessage))
        self.headers_ = headers
        # the body must be a set of bytes
        assert(isinstance(body, bytes))
        self.message_ = body
    
    def validate_tag_list(self, tag_list: dict):
        client_ip = tag_list.get('client-ip')

    def validate_tags(self):
        # now we do the rest
        for name, value in self.headers_.items():
            if name == 'Received-SPF':
                # each time we see a Received-SPF, lets examine it
                value = re.sub(r'^\s*pass\s*\(.*\)\s+([\w_-]+=)', r'\1', value)
                value = [x.strip() for x in value.split(';') if x.strip() != '']
                value = dict([split_keypair(x) for x in value])
                self.validate_tag_list(value)

    def explain_record(self, spf_record):
        record_atoms = spf_record.split(' ')
        mechanism = pp.one_of("all include a mx ptr ip4 ip6 exists")
        directive = pp.Optional(pp.one_of("+ - ? ~")) + mechanism + pp.Optional(pp.Suppress(":") + pp.Word(pp.printables))

        for atom in record_atoms:
            results = directive.parse_string(atom)
            interpret = []
            for result in results:
                if result == '~':
                    interpret.append('softfail')
                elif result == '-':
                    interpret.append('fail')
                elif result == '?':
                    interpret.append('neutral')
                elif result == '+':
                    interpret.append('pass')
                elif result in ('all', 'include'):
                    interpret.append(result)
                else:
                    # filename or other atom (not enough validation yet)
                    interpret.append(result)
                    #raise ValueError(f'unhandled directive part {result}')

            logger.info('SPF directive: ' + (' '.join(interpret)))
            # check to see if there is a directive


    def validate_dns_record(self):
        # lookup the SPF record for this domain
        logger.info(f'SPF attempting to find DNS record for {self.domain_}')

        for txt_record in dns.resolver.resolve(f'{self.domain_}', 'TXT'):
            txt_record = txt_record.to_text().strip('"')
            if txt_record.startswith('v=spf1'):
                logger.info(f'SPF record located for {self.domain_}')
                self.explain_record(txt_record[7:].lstrip())
                return
        
        logger.warn(f'SPF record not found for {self.domain_}')

    def validate(self):
        # Get the 'From' header - there maybe more than one, but we need the domain for the origin
        sender = self.headers_.get('From')
        # we are not going to do an official parse of the 'email'
        sender_match = re.match(r'^.*\s*<(\w+)@([a-zA-Z\_\-\.]*)>', sender)
        self.username_ = sender_match.group(1)
        self.domain_ = sender_match.group(2)

        logger.info(f'Validating username = {self.username_}')
        logger.info(f'Validating domain = {self.domain_}')

        self.validate_dns_record()
        self.validate_tags()
