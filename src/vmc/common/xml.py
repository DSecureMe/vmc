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

from defusedxml import ElementTree


def iter_elements_by_name(handle, name: str):
    events = ElementTree.iterparse(handle, events=("start", "end",))
    _, root = next(events)  # pylint: disable=stop-iteration-return
    for event, elem in events:
        if event == "end" and elem.tag == name:
            yield elem
            root.clear()


def get_root_element(file):
    return ElementTree.parse(file).getroot()

