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
from simple_history.admin import SimpleHistoryAdmin

from vmc.knowledge_base.models import Cve, Cwe, Cpe, Exploit
from vmc.knowledge_base.tasks import update_cve_cwe, update_cpe


class CveAdmin(SimpleHistoryAdmin):
    change_list_template = "knowledge_base/admin/cve_change_list.html"
    list_display = ('id', 'cwe', 'base_score_v2', 'base_score_v3', 'published_date', 'last_modified_date')
    list_filter = ('access_vector_v2', 'access_complexity_v2', 'authentication_v2', 'confidentiality_impact_v2',
                   'integrity_impact_v2', 'availability_impact_v2', 'attack_vector_v3', 'attack_complexity_v3',
                   'user_interaction_v3', 'scope_v3', 'confidentiality_impact_v3', 'integrity_impact_v3',
                   'availability_impact_v3')
    search_fields = (
        'id',
    )

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


class CpeAdmin(admin.ModelAdmin):
    change_list_template = "knowledge_base/admin/cpe_change_list.html"
    list_display = ('vendor', 'title', )
    search_fields = ('vendor', 'title', )

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                r'import/',
                self.admin_site.admin_view(self.import_data),
                name='knowledge-base-cpe-import',
            )
        ]
        return custom_urls + urls

    def import_data(self, request):
        update_cpe.delay()
        self.message_user(request, "Importing started.")
        return HttpResponseRedirect("../")


admin.site.register(Cve, CveAdmin)
admin.site.register(Cwe, SimpleHistoryAdmin)
admin.site.register(Exploit)
admin.site.register(Cpe, CpeAdmin)
