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

from django_celery_beat.admin import PeriodicTaskAdmin as CeleryPeriodicTaskAdmin
from django_celery_beat.admin import PeriodicTaskForm as CeleryPeriodicTaskForm
from django_celery_beat.admin import TaskSelectWidget as CeleryTaskSelectWidget
from django_celery_beat.models import PeriodicTask


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


admin.site.unregister(PeriodicTask)
admin.site.register(PeriodicTask, PeriodicTaskAdmin)
