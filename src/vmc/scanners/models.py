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

from django.db import models
from django.core.exceptions import ValidationError
from vmc.common.models import ConfigBaseModel
from vmc.elasticsearch.models import Tenant


class Config(ConfigBaseModel):
    last_scans_pull = models.DateTimeField(default=None, null=True, blank=True)
    tenant = models.ForeignKey(Tenant, null=True, blank=True, on_delete=models.CASCADE)
    scanner = models.CharField(max_length=128)

    class Meta:
        db_table = 'scanners'

    def clean(self):
        if not self.pk and Config.objects.filter(tenant=self.tenant, scanner=self.scanner).exists():
            raise ValidationError('Only one type of Scanner can be assigned to one Tenant')
