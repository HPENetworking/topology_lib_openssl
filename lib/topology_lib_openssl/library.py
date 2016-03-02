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
                     state=None, city=None, company=None, section=None,
                     name=None, email=None, password=None,
                     optional_company=None, shell=None):
    """
    If the cert and key already existis remove it, and generate a new one
    into the directory
    """
    # cert_file = "server.crt"
    key_file = "server-private.key"

    if key_size is None:
        key_size = '1024'

    if shell is None:
        shell = 'bash'

    verify_create_directory(enode, cert_dir, shell)
    cmd_genrsa = 'openssl genrsa -des3 -passout pass:x -out server.pass.key\
             ' + key_size
    result_genrsa = enode(cmd_genrsa, shell=shell)
    if '...............+++' not in str(result_genrsa):
        print("error")

    cmd_genkey = 'openssl rsa -passin pass:x -in server.pass.key -out\
             ' + key_file
    result_genkey = enode(cmd_genkey, shell=shell)
    if 'writing RSA key' not in str(result_genkey):
        print('Error')

    # RM server pass key

    cmd_gencsr = 'openssl req -new -key ' + key_file + ' -out server.csr'
    set_trace()
    result_gencsr = enode(cmd_gencsr, shell=shell)
    print(result_gencsr)


def verify_create_directory(enode, cert_dir=None, shell=None):

    # Verify directory is not empty, if it is set /etc/ssl/certs/ as direcotry
    if cert_dir is None:
        cert_dir = '/etc/ssl/certs/'

    # check if directory exists
    cmd_cd = 'cd ' + cert_dir
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
    'verify_create_directory',
    'generate_rsa_key'
]
