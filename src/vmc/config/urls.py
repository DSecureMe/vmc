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
from django.shortcuts import redirect
from django.urls import path, include
from vmc.knowledge_base.views import update_knowledge_base
from vmc.ralph.views import get_asset_manager_config
from vmc.vulnerabilities.views import search_vulnerabilities
from vmc.scanners.views import download_scan

admin.site.site_header = "VMC Admin Panel"
admin.site.site_title = "VMC Admin Panel"
admin.site.index_title = "Dashboard"

urlpatterns = [
    path('', lambda request: redirect('admin/', permanent=False)),
    path('admin/', admin.site.urls),
    path('admin/knowlege-base/update', update_knowledge_base, name='update_knowledge_base'),
    path('api/v1/assets-manager/config', get_asset_manager_config, name='get_asset_manager_config'),
    path('api/v1/vulnerabilities', search_vulnerabilities, name='search_vulnerabilities'),
    path('api/v1/scans/backups/<str:scan_id>', download_scan, name='download_scan'),
    path('api/v1/webhook/', include('vmc.webhook.urls', namespace='webhook'))
]
