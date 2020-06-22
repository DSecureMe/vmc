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
from django.template.defaultfilters import pluralize
from django.db.models import When, Value, Case

from django_celery_beat.admin import PeriodicTaskAdmin as CeleryPeriodicTaskAdmin
from django_celery_beat.admin import PeriodicTaskForm as CeleryPeriodicTaskForm
from django_celery_beat.admin import TaskSelectWidget as CeleryTaskSelectWidget
from django_celery_beat.models import PeriodicTask

from vmc.common.tasks import start_workflow


class TaskSelectWidget(CeleryTaskSelectWidget):

    def tasks_as_choices(self):
        _ = self._modules  # noqa
        tasks = list(sorted(name for name in self.celery_app.tasks
                            if not name.startswith('celery.') and not name.startswith('vmc.')))
        return (('', ''),) + tuple(zip(tasks, tasks))


class TaskChoiceField(forms.ChoiceField):

    widget = TaskSelectWidget

    def valid_value(self, value):
        return True


class PeriodicTaskForm(CeleryPeriodicTaskForm):
    task = TaskChoiceField(
        label='Task (registered)',
        required=False,
    )
    regtask = None


class PeriodicTaskAdmin(CeleryPeriodicTaskAdmin):
    form = PeriodicTaskForm
    fieldsets = (
        (None, {
            'fields': ('name', 'task', 'enabled', 'description',),
            'classes': ('extrapretty', 'wide'),
        }),
        ('Schedule', {
            'fields': ('interval', 'crontab', 'solar',
                       'start_time', 'one_off'),
            'classes': ('extrapretty', 'wide'),
        }),
        ('Arguments', {
            'fields': ('args', 'kwargs'),
            'classes': ('extrapretty', 'wide', 'collapse', 'in'),
        }),
        ('Execution Options', {
            'fields': ('expires', 'queue', 'exchange', 'routing_key'),
            'classes': ('extrapretty', 'wide', 'collapse', 'in'),
        }),
    )

    def get_queryset(self, request):
        qs = super(PeriodicTaskAdmin, self).get_queryset(request)
        return qs.exclude(name__contains='celery.')


class ConfigBaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'host', 'tenant', 'enabled', 'last_success_date', 'last_update_status')
    actions = ('enable_configs', 'disable_configs', 'toggle_configs', 'run_configs')
    readonly_fields = [
        'created_date', 'modified_date', 'last_update_status',
        'last_success_date', 'error_description'
    ]
    model = None

    def _message_user_about_update(self, request, rows_updated, verb):
        self.message_user(
            request,
            '{0} config{1} {2} successfully {3}'.format(
                rows_updated,
                pluralize(rows_updated),
                pluralize(rows_updated, 'was,were'),
                verb,
            ),
        )

    def enable_configs(self, request, queryset):
        rows_updated = queryset.update(enabled=True)
        self._message_user_about_update(request, rows_updated, 'enabled')
    enable_configs.short_description = 'Enable selected configs'

    def disable_configs(self, request, queryset):
        rows_updated = queryset.update(enabled=False)
        self._message_user_about_update(request, rows_updated, 'disabled')
    disable_configs.short_description = 'Disable selected configs'

    def _toggle_configs_activity(self, queryset):
        return queryset.update(enabled=Case(
            When(enabled=True, then=Value(False)),
            default=Value(True),
        ))

    def toggle_configs(self, request, queryset):
        rows_updated = self._toggle_configs_activity(queryset)
        self._message_user_about_update(request, rows_updated, 'toggled')
    toggle_configs.short_description = 'Toggle activity of selected configs'

    def run_configs(self, request, queryset):
        for config in queryset:
            config.set_status(status=self.model.Status.PENDING)
            workflow = self.update_workflow(config)
            start_workflow(workflow, config.tenant)

        self.message_user(
            request,
            '{0} config{1} {2} successfully run'.format(
                queryset.count(),
                pluralize(queryset.count()),
                pluralize(queryset.count(), 'was,were'),
            )
        )

    run_configs.short_description = 'Import selected configs'

    def update_workflow(self, config):
        raise NotImplementedError()


admin.site.unregister(PeriodicTask)
admin.site.register(PeriodicTask, PeriodicTaskAdmin)
