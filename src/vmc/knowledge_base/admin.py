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

from django.contrib import admin
from django.http import HttpResponseRedirect
from django.urls import path

from vmc.knowledge_base.models import Cve
from vmc.knowledge_base.tasks import start_update_knowledge_base


class CveAdmin(admin.ModelAdmin):
    actions = None
    change_list_template = "knowledge_base/admin/cve_change_list.html"

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                r'import/',
                self.admin_site.admin_view(self.import_data),
                name='knowledge-base-cve-import',
            )
        ]
        return custom_urls + urls

    def import_data(self, request):
        start_update_knowledge_base.delay()
        self.message_user(request, "Importing started.")
        return HttpResponseRedirect("../")


admin.site.register(Cve, CveAdmin)
