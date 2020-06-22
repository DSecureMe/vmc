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
from django import forms
from django.contrib import admin
from django.forms import PasswordInput

from vmc.scanners.registries import scanners_registry
from vmc.common.admin import ConfigBaseAdmin
from vmc.scanners.models import Config
from vmc.scanners.tasks import get_update_scans_workflow


def get_scanners_choices():
    scanners = scanners_registry.get_scanners()
    return [(s, s.split('.')[-1].capitalize()) for s in scanners]


class ConfigForm(forms.ModelForm):
    scanner = forms.ChoiceField(choices=lambda: get_scanners_choices())

    class Meta:
        model = Config
        widgets = {
            'password': PasswordInput(render_value=True),
        }
        fields = ['name', 'enabled', 'schema', 'host', 'port', 'username', 'insecure', 'password', 'scanner', 'tenant']


class ConfigAdmin(ConfigBaseAdmin):
    model = Config
    form = ConfigForm

    def update_workflow(self, config):
        return get_update_scans_workflow(config)


admin.site.register(Config, ConfigAdmin)
