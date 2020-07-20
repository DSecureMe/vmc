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

from django.utils.timezone import now
from django.db import models


class BaseModel(models.Model):
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class ConfigBaseModel(BaseModel):
    class Status(Enum):
        PENDING = 'Pending'
        IN_PROGRESS = 'In Progress'
        ERROR = 'Error'
        SUCCESS = 'Success'

        @classmethod
        def choices(cls) -> List[tuple]:
            return [(key.value, key.name) for key in cls]

    SCHEMA = (
        ('http', 'http'),
        ('https', 'https')
    )
    name = models.CharField(max_length=128)
    schema = models.CharField(choices=SCHEMA, default='http', max_length=5)
    host = models.CharField(max_length=128)
    port = models.PositiveSmallIntegerField()
    username = models.TextField()
    password = models.TextField()
    insecure = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    last_success_date = models.DateTimeField(null=True, blank=True)
    last_update_status = models.CharField(max_length=16, choices=Status.choices(), blank=True, null=True)
    error_description = models.TextField(blank=True, null=True)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name

    def set_status(self, status, error_description=''):
        if status == ConfigBaseModel.Status.SUCCESS:
            self.last_success_date = now()

        self.error_description = error_description
        self.last_update_status = status.value
        self.save(update_fields=['last_update_status', 'error_description', 'last_success_date'])

    def get_url(self) -> str:
        return F'{self.schema}://{self.host}:{self.port}'

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        self.full_clean()
        return super().save(force_insert=force_insert, force_update=force_update,
                            using=using, update_fields=update_fields)
