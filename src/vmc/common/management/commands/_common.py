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
            print(F'Checking for {host} {port}')
            with socket.create_connection((host, port), timeout=timeout):
                break
        except OSError:
            print(F'Unable to connect to {host} {port}, waiting...')
            time.sleep(5.0)
            if time.perf_counter() - start_time >= timeout:
                print(F'Waited too long for the port {port} on host {host} to start accepting connections.')
                return False
    print(F'Host {host} and port {port} is ready')
    return True


def wait_for_socket(unix_socket, timeout=60.0):
    start_time = time.perf_counter()
    while True:
        print(F'Checking for {unix_socket}')
        if Path(unix_socket).is_socket():
            break
        else:
            print(F'Unable to connect to {unix_socket}, waiting...')
            time.sleep(5.0)
            if time.perf_counter() - start_time >= timeout:
                print(F'Waited too long for the unix socket {unix_socket}.')
                return False
    print(F'Socket {unix_socket} is ready')
    return True


def get_config(key, default):
    return CFG[key] if CFG and key in CFG else default
