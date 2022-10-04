# cs6387-email-validator
An application that parses the data from an e-mail message's headers and validates the DKIM and SPF components.

# Running

## Basic usage

./email-validator.py --file <filename>.eml --with-spf --with-dkim

This will tell the application to run the validator on the provided file.  The parser works with EML files.  It might work
with other formats, but your mileage may vary.

## Debugging

You want more detail?

Just add the --debug option and it will set the logger to debug mode.
