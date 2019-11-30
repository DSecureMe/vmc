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

from vmc.assets.models import Port, Asset
from vmc.common.models import BaseModel
from vmc.knowledge_base.models import Cve


class Vulnerability(BaseModel):
    asset = models.ForeignKey(Asset, on_delete=models.DO_NOTHING, null=True)
    cve = models.ForeignKey(Cve, on_delete=models.DO_NOTHING, null=True)
    port = models.ForeignKey(Port, on_delete=models.CASCADE, null=True, blank=True)
    description = models.TextField()
    solution = models.TextField(null=True, blank=True)
    exploit_available = models.BooleanField(default=False)

    @property
    def get_asset(self):
        return self.asset.ip_address

    @property
    def get_entry_cve(self):
        return self.cve.id

    @property
    def get_entry_base_score_v2(self):
        return self.cve.base_score_v2

    @property
    def get_port(self):
        return str(self.port)

    def __str__(self):
        return 'Asset: {}, Port: {}, CVE: {}'.format(self.asset.ip_address, self.port.number, self.cve.id)
