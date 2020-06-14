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
import concurrent.futures

from io import BytesIO
from zipfile import ZipFile
from vmc.config.celery import app as celery_app


class ThreadPoolExecutor:
    def __init__(self):
        self._executors = concurrent.futures.ThreadPoolExecutor()
        self._pool = []

    def submit(self, method, *args, **kwargs):
        self._pool.append(self._executors.submit(method, *args, **kwargs))

    def wait_for_all(self):
        if self._pool:
            concurrent.futures.wait(self._pool)
            self._pool = []


thread_pool_executor = ThreadPoolExecutor()


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


def handle_ranges(ips: list):

    start_octets = ips[0].split(sep=".")
    end_octets = ips[1].split(sep=".")
    end_length = len(end_octets)
    end = start_octets[:(4 - end_length)]
    end.append(ips[1])
    ip_range = [ips[0], '.'.join(end)]
    return ip_range


def get_workers_count():
    workes = celery_app.control.inspect().stats()
    active_count = 0

    for w in workes.values():
        if 'autoscaler' in w:
            active_count += w['autoscaler']['max']
        elif 'pool' in w and w['pool']['max-concurrency'] > 0:
            active_count += w['pool']['max-concurrency']
        else:
            w += 1

    return active_count
