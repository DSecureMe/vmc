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
from django.contrib import admin

from vmc.common.tasks import workflow_in_progress
from vmc.elasticsearch.models import Config, Tenant


class DisableChangeActionAdmin(admin.ModelAdmin):

    def has_change_permission(self, request, obj=None):
        return False


class ConfigMock:
    def __init__(self, tenant):
        self.tenant = tenant


class TenantAdmin(DisableChangeActionAdmin):

    def has_delete_permission(self, request, obj=None):
        if obj and workflow_in_progress(ConfigMock(obj)):
            return False
        return super().has_delete_permission(request, obj)


class ConfigAdmin(DisableChangeActionAdmin):

    def has_delete_permission(self, request, obj=None):
        if obj:
            for tenant in obj.tenant_set.all():
                if workflow_in_progress(ConfigMock(tenant)):
                    return False
        return super().has_delete_permission(request, obj)


admin.site.register(Config, ConfigAdmin)
admin.site.register(Tenant, TenantAdmin)
