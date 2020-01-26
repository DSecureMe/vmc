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

from elasticsearch_dsl import Date, Keyword, InnerDoc
from vmc.common.enum import TupleValueEnum

from vmc.common.elastic.documents import Document, TupleValueField
from vmc.common.elastic.registers import registry


class Impact(TupleValueEnum):
    LOW = ('L', Decimal('0.5'))
    MEDIUM = ('M', Decimal('1.0'))
    HIGH = ('H', Decimal('1.51'))
    NOT_DEFINED = ('N', Decimal('1.0'))


class AssetInnerDoc(InnerDoc):
    ip_address = Keyword()
    os = Keyword()
    cmdb_id = Keyword()
    confidentiality_requirement = TupleValueField(choice_type=Impact)
    integrity_requirement = TupleValueField(choice_type=Impact)
    availability_requirement = TupleValueField(choice_type=Impact)
    business_owner = Keyword()
    technical_owner = Keyword()
    hostname = Keyword()
    created_date = Date()
    modified_date = Date()
    change_reason = Keyword()


@registry.register_document
class AssetDocument(AssetInnerDoc, Document):
    class Index:
        name = 'asset'

