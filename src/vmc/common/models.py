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

from typing import Type

from django.db import models
from django.forms.models import model_to_dict

from vmc.common.enum import TupleValueEnum


class ModelDiffMixin:

    def __init__(self, *args, **kwargs):
        super(ModelDiffMixin, self).__init__(*args, **kwargs)
        self.__initial = self._dict

    @property
    def diff(self):
        d1 = self.__initial
        d2 = self._dict
        diffs = [(k, (v, d2[k])) for k, v in d1.items() if v != d2[k]]
        return dict(diffs)

    @property
    def has_changed(self):
        return bool(self.diff)

    @property
    def changed_fields(self):
        return self.diff.keys()

    def get_field_diff(self, field_name):
        return self.diff.get(field_name, None)

    def save(self, *args, **kwargs):
        super(ModelDiffMixin, self).save(*args, **kwargs)
        self.__initial = self._dict

    @property
    def _dict(self):
        return model_to_dict(self, fields=[field.name for field in self._meta.fields])


class BaseModel(models.Model, ModelDiffMixin):
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class TupleValueField(models.CharField):

    def __init__(self, *args, choice_type: Type[TupleValueEnum] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.choice_type = choice_type

    def contribute_to_class(self, cls, name, private_only=False):
        super().contribute_to_class(cls, name, private_only)
        if self.choices:
            delattr(cls, 'get_{}_display'.format(self.name))
            setattr(cls, 'get_{}_display'.format(self.name), lambda x: self._get_field_display(x))  # pylint: disable=unnecessary-lambda
            setattr(cls, 'get_{}_value'.format(self.name), lambda x: self._get_field_value(x))  # pylint: disable=unnecessary-lambda

    def _get_field_display(self, model: BaseModel) -> str:
        value = getattr(model, self.attname)
        if value and self.choice_type:
            return self.choice_type(value).name
        return value

    def _get_field_value(self, model: BaseModel) -> [str, float]:
        value = getattr(model, self.attname)
        if value and self.choice_type:
            return self.choice_type(value).float
        return value
