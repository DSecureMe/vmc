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

from decimal import Decimal
from enum import Enum
from typing import List

from vmc.common.enum import TupleValueEnum


class AccessVectorV2(TupleValueEnum):
    LOCAL = ('L', Decimal('0.395'))
    ADJACENT_NETWORK = ('A', Decimal('0.646'))
    NETWORK = ('N', Decimal('1.0'))


class AccessComplexityV2(TupleValueEnum):
    HIGH = ('H', Decimal('0.35'))
    MEDIUM = ('M', Decimal('0.61'))
    LOW = ('L', Decimal('0.71'))


class AuthenticationV2(TupleValueEnum):
    MULTIPLE = ('M', Decimal('0.45'))
    SINGLE = ('S', Decimal('0.56'))
    NONE = ('N', Decimal('0.704'))


class ImpactV2(TupleValueEnum):
    NONE = ('N', Decimal('0.0'))
    PARTIAL = ('P', Decimal('0.275'))
    COMPLETE = ('C', Decimal('0.660'))


class AttackVectorV3(TupleValueEnum):
    NETWORK = ('N', Decimal('0.85'))
    ADJACENT_NETWORK = ('A', Decimal('0.62'))
    LOCAL = ('L', Decimal('0.55'))
    PHYSICAL = ('P', Decimal('0.2'))


class AttackComplexityV3(TupleValueEnum):
    LOW = ('L', Decimal('0.77'))
    HIGH = ('H', Decimal('0.44'))


class UserInteractionV3(TupleValueEnum):
    NONE = ('N', Decimal('0.85'))
    REQUIRED = ('R', Decimal('0.62'))


class ScopeV3(Enum):
    CHANGED = 'C'
    UNCHANGED = 'U'

    @classmethod
    def choices(cls) -> List[tuple]:
        return [(tag.value, tag.name) for tag in cls]

    @classmethod
    def _missing_(cls, key):
        for item in cls:
            if item.name == key:
                return item

        return cls.__missing__(key)


class PrivilegesRequiredV3(Enum):
    NONE = 'N'
    LOW = 'L'
    HIGH = 'H'

    @classmethod
    def choices(cls) -> List[tuple]:
        return [(tag.value, tag.name) for tag in cls]

    @classmethod
    def _missing_(cls, key):
        for item in cls:
            if item.name == key:
                return item

        return cls.__missing__(key)

    def value_with_scope(self, scope: ScopeV3) -> Decimal:
        if self == PrivilegesRequiredV3.NONE:
            return Decimal('0.85')

        if self == PrivilegesRequiredV3.LOW:
            return Decimal('0.68') if scope == ScopeV3.CHANGED else Decimal('0.62')

        return Decimal('0.50') if scope == ScopeV3.CHANGED else Decimal('0.27')


class ImpactV3(TupleValueEnum):
    HIGH = ('H', Decimal('0.56'))
    LOW = ('L', Decimal('0.22'))
    NONE = ('N', Decimal('0'))
