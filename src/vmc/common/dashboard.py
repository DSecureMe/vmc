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
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from django_celery_beat.models import PeriodicTask

from vmc.elasticsearch.models import Tenant, Config as ElasticsearchConfig
from vmc.ralph.models import Config as RalphConfig
from vmc.scanners.models import Config as ScannerConfig
from vmc.webhook.models import TheHive4 as TheHive4Config


def dashboard_callback(request, context):
    context["dashboard_kpi"] = [
        {
            "title": _("Tenants"),
            "metric": Tenant.objects.count(),
            "url": reverse("admin:elasticsearch_tenant_changelist"),
        },
        {
            "title": _("Scanner configs"),
            "metric": ScannerConfig.objects.count(),
            "url": reverse("admin:scanners_config_changelist"),
        },
        {
            "title": _("Ralph configs"),
            "metric": RalphConfig.objects.count(),
            "url": reverse("admin:ralph_config_changelist"),
        },
        {
            "title": _("Elasticsearch configs"),
            "metric": ElasticsearchConfig.objects.count(),
            "url": reverse("admin:elasticsearch_config_changelist"),
        },
        {
            "title": _("TheHive webhooks"),
            "metric": TheHive4Config.objects.count(),
            "url": reverse("admin:webhook_thehive4_changelist"),
        },
        {
            "title": _("Periodic tasks"),
            "metric": PeriodicTask.objects.exclude(name__contains="celery.").count(),
            "url": reverse("admin:django_celery_beat_periodictask_changelist"),
        },
    ]
    return context
