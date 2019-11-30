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

import os
from django.core.management.base import BaseCommand

from vmc.common.management.commands._common import wait_for_db_ready, wait_for_rabbit_ready


class Command(BaseCommand):
    help = 'Runs Monitor for VMC'

    def handle(self, *args, **options):
        self.stdout.write("Starting VMC Scheduler")
        if wait_for_db_ready() and wait_for_rabbit_ready():
            os.system('celery flower -A vmc.config.celery --address=0.0.0.0 --port=8080')
        else:
            self.stdout.write("Unable to start VMC Monitor")
            exit(1)
