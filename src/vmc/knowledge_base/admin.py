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

from vmc.knowledge_base.models import Dummy
from vmc.knowledge_base.tasks import update_cve_cwe


class CveAdmin(admin.ModelAdmin):
    change_list_template = "knowledge_base/admin/cve_change_list.html"

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
        update_cve_cwe.delay()
        self.message_user(request, "Importing started.")
        return HttpResponseRedirect("../")


admin.site.register(Dummy, CveAdmin)
