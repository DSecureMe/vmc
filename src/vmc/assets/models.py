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

from django.db import models

from vmc.common.enum import TupleValueEnum
from vmc.common.models import BaseModel, TupleValueField


class Impact(TupleValueEnum):
    LOW = ('L', Decimal('0.5'))
    MEDIUM = ('M', Decimal('1.0'))
    HIGH = ('H', Decimal('1.51'))
    NOT_DEFINED = ('N', Decimal('1.0'))


class Port(BaseModel):
    number = models.PositiveIntegerField()
    svc_name = models.CharField(max_length=32)
    protocol = models.CharField(max_length=3)

    def __str__(self):
        return str(self.number)


class Asset(BaseModel):
    ip_address = models.CharField(max_length=16)
    mac_address = models.CharField(max_length=17, blank=True)
    os = models.CharField(max_length=128, blank=True)
    responsible_person = models.EmailField(blank=True, null=True)
    confidentiality_requirement = TupleValueField(
        choice_type=Impact,
        choices=Impact.choices(),
        default=Impact.NOT_DEFINED.value,
        max_length=1
    )
    integrity_requirement = TupleValueField(
        choices=Impact.choices(),
        default=Impact.NOT_DEFINED.value,
        choice_type=Impact,
        max_length=1
    )
    availability_requirement = TupleValueField(
        choices=Impact.choices(),
        default=Impact.NOT_DEFINED.value,
        choice_type=Impact,
        max_length=1
    )

    def __str__(self):
        return self.ip_address
