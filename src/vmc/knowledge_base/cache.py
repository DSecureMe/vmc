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

from django.core.cache import cache


class NotificationCache:
    NOTIFICATION_TTL = 86400
    KEY = 'KNOWLEDGE-BASE-NOTIFICATION'
    INITIAL_KEY = 'KNOWLEDGE-BASE-NOTIFICATION-INITIAL'

    @staticmethod
    def set(cve_id: str, created: bool):
        result = cache.get_or_set(NotificationCache.KEY, [], None)
        result.append((cve_id, created))
        cache.set(NotificationCache.KEY, result)

    @staticmethod
    def clear():
        cache.delete(NotificationCache.KEY)
        cache.delete(NotificationCache.INITIAL_KEY)

    @staticmethod
    def get() -> list:
        return cache.get(NotificationCache.KEY, [])

    @staticmethod
    def initial_update(is_initial: bool):
        cache.set(NotificationCache.INITIAL_KEY, is_initial, NotificationCache.NOTIFICATION_TTL)

    @staticmethod
    def is_initial_update() -> bool:
        return cache.get(NotificationCache.INITIAL_KEY, True)
