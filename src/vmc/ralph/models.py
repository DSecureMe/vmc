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
    tenant = models.OneToOneField(Tenant, null=True, blank=True, related_name='tenant', on_delete=models.CASCADE)

    class Meta:
        db_table = 'ralph_config'

    def clean(self):
        super().clean()
        if not self.pk and Config.objects.filter(tenant=self.tenant).exists():
            raise ValidationError('Only one Ralph can be assigned to one Tenant')

