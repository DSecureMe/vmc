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

import time
import socket
import yaml
from pathlib import Path

CFG = None

try:
    from vmc.config.settings import CFG_PATH
    with open(CFG_PATH, 'r') as ymlfile:
        CFG = yaml.safe_load(ymlfile)
except FileNotFoundError:
    pass


def wait_for_port(port, host='localhost', timeout=120.0):
    start_time = time.perf_counter()
    while True:
        try:
            print('Checking for {} {}'.format(host, port))
            with socket.create_connection((host, port), timeout=timeout):
                break
        except OSError:
            print('Unable to connect to {} {}, waiting...'.format(host, port))
            time.sleep(5.0)
            if time.perf_counter() - start_time >= timeout:
                print('Waited too long for the port {} on host {} to start accepting connections.'.format(port, host))
                return False
    print('Host {} and port {} is ready'.format(host, port))
    return True


def wait_for_socket(unix_socket, timeout=60.0):
    start_time = time.perf_counter()
    while True:
        print('Checking for {} '.format(unix_socket))
        if Path(unix_socket).is_socket():
            break
        else:
            print('Unable to connect to {}, waiting...'.format(unix_socket))
            time.sleep(5.0)
            if time.perf_counter() - start_time >= timeout:
                print('Waited too long for the unix socket {}.'.format(unix_socket))
                return False
    print('Socket {} is ready'.format(unix_socket))
    return True


def get_config(key, default):
    return CFG[key] if CFG and key in CFG else default


def wait_for_db_ready():
    db_socket = get_config('database.unix_socket', '')
    if db_socket:
        return wait_for_socket(db_socket)
    return wait_for_port(
        get_config('database.port', 5432),
        get_config('database.host', 'localhost')
    )


def wait_for_rabbit_ready():
    return wait_for_port(
        get_config('rabbitmq.port', 5672),
        get_config('rabbitmq.host', 'localhost')
    )
