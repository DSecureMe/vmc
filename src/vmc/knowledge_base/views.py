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
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import user_passes_test
from vmc.knowledge_base.tasks import start_update_knowledge_base


@user_passes_test(lambda u: u.is_superuser)
def update_knowledge_base(request):
    start_update_knowledge_base.delay()
    messages.add_message(request, messages.INFO, "Update knowledge base started.")
    return HttpResponseRedirect("/")
