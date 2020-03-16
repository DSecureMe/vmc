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
 */
"""
from enum import Enum
from typing import Type

from elasticsearch_dsl import Date, Keyword, CustomField
from elasticsearch_dsl import Document as ESDocument
from django.utils.timezone import now

from vmc.common.enum import TupleValueEnum

from vmc.elasticsearch.signals import post_save


class TupleValueField(CustomField):
    builtin_type = Keyword()

    def __init__(self, *args, choice_type: Type[TupleValueEnum] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.choice_type = choice_type

    def _serialize(self, data):
        return self.choice_type(data).name

    def _deserialize(self, data):
        return self.choice_type(data)

    @property
    def name(self):
        return self.choice_type(self.value).name

    @property
    def value(self):
        return self.choice_type(self.value).value

    @property
    def second_value(self):
        return self.choice_type(self.value).second_value


class EnumField(CustomField):
    builtin_type = Keyword()

    def __init__(self, *args, choice_type: Type[Enum] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.choice_type = choice_type

    def _serialize(self, data):
        return self.choice_type(data).name

    def _deserialize(self, data):
        return self.choice_type(data)


class Document(ESDocument):
    BASE_DOCUMENT_FIELDS = ['_id', 'created_date', 'modified_date', 'change_reason', 'BASE_DOCUMENT_FIELDS']
    created_date = Date()
    modified_date = Date()
    change_reason = Keyword()

    def save(self, **kwargs):
        date = now()
        if not self.created_date:
            self.created_date = date
        self.modified_date = date
        super().save(** kwargs)
        post_save.send(sender=type(self), instance=self, created=(self.created_date == self.modified_date))
        return self

    def update(self, document, using=None, index=None, refresh=False):
        for name in self.get_fields_name():
            if name not in Document.BASE_DOCUMENT_FIELDS:
                setattr(self, name, getattr(document, name))
        self.save(using=using, index=index, refresh=refresh)
        return self

    def has_changed(self, other):
        changed_fields = []
        for name in self.get_fields_name():
            if name not in Document.BASE_DOCUMENT_FIELDS and getattr(self, name) != getattr(other, name):
                changed_fields.append(name)
        return changed_fields

    def __hash__(self):
        return id(self)

    def clone(self, without_fields: list = None):
        if not without_fields:
            without_fields = []

        new_obj = self.__class__()
        for name in self.get_fields_name():
            if name not in without_fields and getattr(self, name, None):
                setattr(new_obj, name, getattr(self, name))
        return new_obj

    @classmethod
    def get_index(cls, config):
        if config:
            from vmc.elasticsearch.registries import registry
            return registry.get_index_for_tenant(config.tenant, cls)
        return cls.Index.name

    @classmethod
    def get_fields_name(cls):
        return [name for name in cls._doc_type.mapping]