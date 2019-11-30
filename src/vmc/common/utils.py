"""
 * Licensed to DSecure.me under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. DSecure.me licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
"""

import gzip

import requests

from io import BytesIO
from zipfile import ZipFile


def is_downloadable(url: str, verify: bool = True) -> bool:
    h = requests.head(url, allow_redirects=True, verify=verify)
    header = h.headers
    content_type = header.get('Content-Type')
    if 'text' in content_type.lower():
        return False
    if 'html' in content_type.lower():
        return False
    return True


def get_file(url: str, verify: bool = True) -> [BytesIO, None]:
    content = None
    if is_downloadable(url, verify):
        response = requests.get(url, verify=verify)

        if response.status_code == 200:

            if 'gzip' in response.headers.get('Content-Type'):
                content = BytesIO(gzip.decompress(response.content))
            elif 'zip' in response.headers.get('Content-Type'):
                zipfile = ZipFile(BytesIO(response.content))
                file = zipfile.open(zipfile.namelist()[0])
                content = BytesIO(file.read())
            else:
                content = response.content

    return content
