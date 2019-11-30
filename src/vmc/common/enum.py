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

from enum import Enum
from typing import List


class TupleValueEnum(Enum):

    @classmethod
    def choices(cls) -> List[tuple]:
        return [(tag.value, tag.name) for tag in cls]

    @classmethod
    def _missing_(cls, key):
        for item in cls:
            if item.value[0] == key:
                return item

        for item in cls:
            if item.name == key:
                return item

        return cls.__missing__(key)

    @property
    def value(self):
        return super().value[0]

    @property
    def float(self) -> float:
        return float(super().value[1])
