import logging

from email.message import EmailMessage

logger = logging.getLogger(__name__)

# a module for validating the SPF

class SPF_Validator:
    def __init__(self, headers: EmailMessage, body: bytes):
        assert(isinstance(headers, EmailMessage))
        self.headers_ = headers
        # the body must be a set of bytes
        assert(isinstance(body, bytes))
        self.message_ = body
    
    def validate(self):
        pass
