# Pull base image.
FROM python:3.10.7

# Set environment variables.
ENV HOME /root

# Define working directory.
WORKDIR /usr/src/app/email-validator

COPY *.py /usr/src/app/email-validator/

RUN pip3 install dnspython pyparsing rsa

# Define default command.
CMD ["bash"]
