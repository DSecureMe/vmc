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

from vmc.elasticsearch.models import Tenant
from vmc.scanners.registries import scanners_registry
from vmc.common.admin import ConfigBaseAdmin
from vmc.scanners.models import Config
from vmc.scanners.tasks import get_update_scans_workflow


class ConfigForm(forms.ModelForm):
    class Meta:
        model = Config
        widgets = {
            'password': PasswordInput(),
        }
        fields = ['name', 'enabled', 'schema', 'host', 'port', 'filter',
                  'username', 'insecure', 'password', 'scanner', 'tenant']

    def __init__(self, *args, **kwargs):
        super(ConfigForm, self).__init__(*args, **kwargs)

        r = []
        if kwargs.get('instance', None) and kwargs['instance'].tenant:
            r += [(kwargs['instance'].tenant.id, kwargs['instance'].tenant.name)]

        self.fields['tenant'] = forms.ChoiceField(choices=ConfigForm.get_not_related_tenants() + r)
        self.fields['scanner'] = forms.ChoiceField(choices=ConfigForm.get_scanners_choices())

    @staticmethod
    def get_not_related_tenants():
        return [(x.id, x.name) for x in Tenant.objects.filter(config=None)]

    @staticmethod
    def get_scanners_choices():
        scanners = scanners_registry.get_scanners()
        return [(s, s.split('.')[-1].capitalize()) for s in scanners]


class ConfigAdmin(ConfigBaseAdmin):
    model = Config
    form = ConfigForm

    def update_workflow(self, config):
        return get_update_scans_workflow(config)


admin.site.register(Config, ConfigAdmin)
