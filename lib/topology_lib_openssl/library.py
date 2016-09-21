# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
topology_lib_openssl communication library implementation.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

# Add your library functions here.


def generate_rsa_key(enode, switch_ip, cert_directory='/etc/ssl/certs/',
                     key_directory='/etc/ssl/private/', key_size=None,
                     country='CR', state='HE', location='Heredia',
                     organization='HPE', organization_unit='Aruba',
                     name=None, shell=None, cert_file=None, key_file=None):
    """
    If the cert and key already existis rewrite it, and generate a new one
    into the directory
    """
    if cert_file is None:
        cert_file = "server.crt"

    if key_file is None:
        key_file = "server-private.key"

    if shell is None:
        shell = 'bash'

    generate_key_pass(enode, shell, key_size)
    generate_key(enode, shell, key_file)
    generate_csr(enode, switch_ip, shell, key_file, country, state, location,
                 organization, organization_unit, name)
    generate_crt(enode, shell, key_file, cert_file)
    move_directory(enode, [cert_file, key_file],
                   [cert_directory, key_directory], shell)


def generate_key_pass(enode, shell, key_size=None):

    if key_size is None:
        key_size = '1024'

    # Generate server.pass.key
    cmd_genrsa = ('openssl genrsa -des3 -passout pass:x -out server.pass.key '
                  '' + key_size)
    result_genrsa = enode(cmd_genrsa, shell=shell)

    assert 'Generating RSA private key' in str(result_genrsa), \
        'The server.pass.key is not generated as expected'


def generate_key(enode, shell, key_file):

    # Generate server-private.key
    cmd_genkey = ('openssl rsa -passin pass:x -in server.pass.key -out ' +
                  key_file)
    result_genkey = enode(cmd_genkey, shell=shell)

    assert 'writing RSA key' in str(result_genkey), \
        'The server-private-key is not generated as expected'


def generate_csr(enode, switch_ip, shell, key_file, country=None,
                 state=None, location=None, organization=None,
                 organization_unit=None, name=None):

    if name is None:
        name = switch_ip

    subj = '"/"C={}"/"ST={}"/"L={}"/"O={}"/"OU={}"/"CN={}'.format(
        country, state, location, organization, organization_unit, name)

    # Generate server.csr
    cmd_gencsr = 'openssl req -new -key {} -out server.csr -subj {}'.format(
        key_file, subj)

    # result_gencsr = enode(cmd_gencsr, shell=shell)
    enode(cmd_gencsr, shell=shell)

    cmd_ls = 'ls {}'.format(key_file)
    result_ls = enode(cmd_ls, shell=shell)
    assert 'No such file or directory' not in result_ls, \
        '{} is expected to exist'.format(key_file)


def generate_crt(enode, shell, key_file, cert_file):

    # Generate server.crt
    cmd_gencrt = ('openssl x509 -req -days 365 -in server.csr -signkey {} '
                  '-out {}').format(key_file, cert_file)
    result_gencrt = enode(cmd_gencrt, shell=shell)
    assert 'Signature ok' in result_gencrt, \
        '{} is not generated as expected'.format(cert_file)


def move_directory(enode, files, directories, shell=None):

    for file, directory in zip(files, directories):
        # check if directory exists
        dir_exists = '[ -d {} ] && echo yes'.format(directory)
        file_exists = enode(dir_exists, shell)
        if file_exists != 'yes':
            # creates the file
            cmd_mkdir = 'mkdir {}'.format(directory)
            result_mkdir = enode(cmd_mkdir, shell=shell)
            assert '' == result_mkdir, \
                'Unable to create directoty ' + directory

        cmd_mv = 'mv {} {}'.format(file, directory)
        result_mv = enode(cmd_mv, shell)
        assert '' == result_mv, \
            'Unable to move the file {} to {}'.format(file, directory)


__all__ = [
    'generate_rsa_key'
]
