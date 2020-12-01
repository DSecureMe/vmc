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
import hashlib
from django.db import models
from django.core.exceptions import ValidationError
from vmc.common.models import ConfigBaseModel, BaseModel
from vmc.elasticsearch.models import Tenant


class Config(ConfigBaseModel):
    last_scans_pull = models.DateTimeField(default=None, null=True, blank=True)
    tenant = models.OneToOneField(Tenant, null=True, blank=True, on_delete=models.CASCADE)
    scanner = models.CharField(max_length=128)
    filter = models.CharField(max_length=256, null=True, blank=True)

    __original_tenant = None

    class Meta:
        db_table = 'scanners'

    def __init__(self, *args, **kwargs):
        super(Config, self).__init__(*args, **kwargs)
        self.__original_tenant = self.tenant

    def clean(self):
        super(Config, self).clean()
        if not self.pk and Config.objects.filter(tenant=self.tenant).exists():
            raise ValidationError('Only one type of Scanner can be assigned to one Tenant')

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        if self.tenant != self.__original_tenant:
            self.last_scans_pull = None

        super(Config, self).save(force_insert=force_insert, force_update=force_update,
                                      using=using, update_fields=update_fields)
        self.__original_tenant = self.tenant
        return self


class Scan(BaseModel):
    config = models.ForeignKey(Config, on_delete=models.SET_NULL, null=True)
    file = models.TextField()
    file_id = models.CharField(max_length=64)

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        self.file_id = hashlib.sha256(self.file.encode('utf-8')).hexdigest().lower()
        return super(Scan, self).save(force_insert=force_insert, force_update=force_update,
                                      using=using, update_fields=update_fields)
