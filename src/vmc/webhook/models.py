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
from django.core.exceptions import ValidationError
from django.db import models

from vmc.common.models import BaseModel


class TheHive4LogConverter(BaseModel):
    log_message = models.TextField()
    tag = models.CharField(max_length=128)

    def __str__(self):
        return F'Convert log message {self.log_message} to {self.tag} tag'


class TheHive4(BaseModel):
    SCHEMA = (
        ('http', 'http'),
        ('https', 'https')
    )
    name = models.CharField(max_length=128)
    schema = models.CharField(choices=SCHEMA, default='http', max_length=5)
    host = models.CharField(max_length=128)
    port = models.PositiveSmallIntegerField()
    token = models.CharField(max_length=256)
    insecure = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    vulnerability_status_converter = models.ManyToManyField(TheHive4LogConverter)

    def get_url(self) -> str:
        return F'{self.schema}://{self.host}:{self.port}'

    def __str__(self):
        return self.name

    def save(self,  force_insert=False, force_update=False, using=None,
             update_fields=None):
        if not self.pk and TheHive4.objects.exists():
            raise ValidationError('There can be only one TheHive4 configuration')
        return super().save(force_insert=force_insert, force_update=force_update, using=using,
                            update_fields=update_fields)
