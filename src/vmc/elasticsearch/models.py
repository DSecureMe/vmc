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

import importlib

from django.db import models
from slugify import slugify
from vmc.common.models import BaseModel


class Config(BaseModel):
    name = models.CharField(max_length=128)
    prefix = models.CharField(max_length=128)

    class Meta:
        db_table = 'elasticsearch_config'

    def __str__(self):
        return self.name


class Tenant(BaseModel):
    name = models.CharField(max_length=128)
    slug_name = models.CharField(max_length=128)
    elasticsearch_config = models.ForeignKey(Config, on_delete=models.DO_NOTHING)

    class Meta:
        db_table = 'elasticsearch_tenant'

    def __str__(self):
        return self.name

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        from vmc.elasticsearch.registries import registry

        if not self.modified_date:
            self.slug_name = slugify(self.name, to_lower=True)

        super().save(force_insert=force_insert, force_update=force_update,
                     using=using, update_fields=update_fields)
        registry.register_new_tenant(self)
        return self


class DocumentRegistry(BaseModel):
    index_name = models.CharField(max_length=256)
    tenant = models.ForeignKey(Tenant, on_delete=models.DO_NOTHING)
    module = models.CharField(max_length=256)
    document = models.CharField(max_length=256)

    class Meta:
        db_table = 'elasticsearch_document_registry'

    def tenant_elasticsearch_config_name(self):
        return self.tenant.elasticsearch_config.name

    def tenant_name(self):
        return self.tenant.name

    def get_document(self):
        module = importlib.import_module(self.module)
        return getattr(module, self.document)
