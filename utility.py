import base64
import dns.resolver
import dns.rdtypes
import rsa

from pyparsing import Optional, Suppress
from pyparsing import pyparsing_common, quoted_string, rest_of_line

def split_keypair(value: str):
    index = value.find('=')
    if index == -1:
        return (value)
    
    return (value[0:index], value[index+1:])

def unpack_public_key(resource_record: str):
    string_list = [v.strip() for v in resource_record.split(';')]
    # parse the tag lists, but the last element may not be a tag list
    tag_list = pyparsing_common.identifier + Optional(Suppress('=') + rest_of_line)
    tag_list = [tag_list.parse_string(x).as_list() for x in string_list]
    tag_dict = dict([elem for elem in tag_list if len(elem) == 2])
    # check the tag list for the required elements
    version = tag_dict.get('v', 'DKIM1') # RECOMMENDED
    if version != 'DKIM1':
        raise ValueError('version not supported')

    key_type = tag_dict.get('k', 'rsa') # OPTIONAL
    if key_type != 'rsa':
        raise ValueError(f'key type {key_type} not supported')
    
    public_key_encoded = tag_dict['p'] # REQUIRED
    public_key_encoded = base64.b64decode(public_key_encoded)
    return rsa.PublicKey.load_pkcs1_openssl_der(public_key_encoded)

def get_public_key(selector, domain):
    dns_query = f'{selector}._domainkey.{domain}'
    dns_record = dns.resolver.resolve(dns_query, 'TXT')
    dns_record = b''.join([x.strip() for x in dns_record[0].strings])
    dns_record = dns_record.decode()

    return unpack_public_key(dns_record)

def test_complete():
    public_key = get_public_key('protonmail3', 'protonmail.com.')
    print(public_key)

if __name__ == '__main__':
    test_complete()