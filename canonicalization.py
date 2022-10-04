from abc import abstractmethod
import re

# this module helps with the canonicalization requirement for DKIM verification

def strip_trailing_lines(message_part: bytes):
    assert(isinstance(message_part, bytes))
    # trim the empty lines at the end of the message body
    while message_part.endswith(b'\r\n'):
        message_part = message_part[:-2]
    
    if message_part == b'' or message_part is None:
        return b'\r\n'
    
    return message_part + b'\r\n'

def reduce_whitespace(input):
    if input is None:
        return None
    elif isinstance(input, bytes):
        return re.sub(b'[\t ](\r?\n)', b'\r\n', input, flags = re.MULTILINE)
    elif isinstance(input, str):
        return re.sub('[\t ](\r?\n)', '\r\n', input, flags = re.MULTILINE)

    print(type(input))
    raise ValueError('invalid input to function')

def with_strip(input):
    if input is None:
        return None
    elif isinstance(input, bytes):
        return input.strip()
    elif isinstance(input, str):
        return input.strip()

class Canonicalizer:
    apply_header = None
    apply_body = None

simple = Canonicalizer()
simple.apply_body = strip_trailing_lines
simple.apply_header = lambda x: x

relaxed = Canonicalizer()
relaxed.apply_body = lambda x: strip_trailing_lines(reduce_whitespace(x))
relaxed.apply_header = lambda x: with_strip(reduce_whitespace(x))