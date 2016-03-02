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
from pytest import set_trace

# Add your library functions here.


def generate_rsa_key(enode, cert_dir=None, key_size=None, country=None,
                     state=None, location=None, organization=None,
                     organization_unit=None, name=None, shell=None):
    """
    If the cert and key already existis remove it, and generate a new one
    into the directory
    """
    cert_file = "server.crt"
    key_file = "server-private.key"
    subj = '"/"'

    if country is not None:
        subj += 'C=' + country + '/'
    if state is not None:
        subj += 'ST=' + state + '/'
    if location is not None:
        subj += 'L=' + location + '/'
    if organization is not None:
        subj += 'O=' + organization + '/'
    if organization_unit is not None:
        subj += 'OU=' + organization_unit + '/'
    if name is not None:
        subj += 'CN=' + name + '/'

    if key_size is None:
        key_size = '1024'

    if shell is None:
        shell = 'bash'

#    verify_create_directory(enode, cert_dir, shell)

    # Generate server.pass.key
    cmd_genrsa = 'openssl genrsa -des3 -passout pass:x -out server.pass.key\
             ' + key_size
    result_genrsa = enode(cmd_genrsa, shell=shell)
    assert '...............+++' not in str(result_genrsa), 'The \
            server.pass.key is not generated as expected'

    # Generate server-private.key
    cmd_genkey = 'openssl rsa -passin pass:x -in server.pass.key -out\
             ' + key_file
    result_genkey = enode(cmd_genkey, shell=shell)
    assert 'writing RSA key' not in str(result_genkey), 'The \
            server-private-key is not generated as expected'

    # Generate server.csr
    cmd_gencsr = 'openssl req -new -key ' + key_file + ' -out server.csr\
 -subj ' + subj
    # result_gencsr = enode(cmd_gencsr, shell=shell)
    enode(cmd_gencsr, shell=shell)

    cmd_ls = 'ls'
    result_ls = enode(cmd_ls, shell=shell)
    assert key_file not in result_ls, key_file + 'is expected to exist'

    # Generate server.crt
    cmd_gencrt = 'openssl x509 -req -days 365 -in server.csr -signkey\
 ' + key_file + ' -out ' + cert_file
    result_gencrt = enode(cmd_gencrt, shell=shell)
    assert 'Signature ok'not in result_gencrt, cert_file + ' is not generated \
            as expected'


def copy_expected_directory(enode, cert_dir=None, shell=None):

    # Verify directory is not empty, if it is set /etc/ssl/certs/ as direcotry
    if cert_dir is None:
        cert_dir = '/etc/ssl/certs/'

    # check if directory exists
    cmd_cd = 'cd ' + cert_dir
    set_trace()
    file_exists = enode(cmd_cd, shell=shell)
    if 'No such file or directory' in str(file_exists):
        # creates the file
        cmd_mkdir = 'mkdir ' + cert_dir
        enode(cmd_mkdir, shell=shell)
        enode(cmd_cd, shell=shell)

    cmd_pwd = 'pwd'
    result_current_directory = enode(cmd_pwd, shell=shell)
    if cert_dir not in str(result_current_directory):
        # return there is a problem with the diectory
        print("error")


__all__ = [
    'generate_rsa_key'
]
