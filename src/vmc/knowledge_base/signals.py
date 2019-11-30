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

from django.dispatch import Signal
from django.db.models.signals import post_save

from vmc.knowledge_base.cache import NotificationCache
from vmc.knowledge_base.models import Cve

knowledge_base_update_finished = Signal(providing_args=["cves"])


def _cve_saved(**kwargs):
    NotificationCache.set(kwargs['instance'].id, kwargs['created'])


post_save.connect(_cve_saved, sender=Cve)
