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
import re
from django.http import HttpResponse
from django.shortcuts import redirect
from rest_framework.generics import get_object_or_404
from rest_framework.exceptions import NotFound
from pathlib import Path

from vmc.scanners.models import Scan


def download_scan(request, scan_id):

    if not request.user.is_authenticated:
        return redirect(F'/admin/login/?next={request.path}')

    if not re.match(r"[a-f0-9]{64}", scan_id):
        raise NotFound

    if request.method == 'GET' and scan_id:
        scan = get_object_or_404(Scan, file_id=scan_id)
        file_path = Path(scan.file)
        with file_path.open(mode="rb") as file_handle:
            response = HttpResponse(file_handle, content_type="text/xml")
            response["Content-Disposition"] = F"scan_file; filename={file_path.name}"
            response["Content-Length"] = str(file_path.stat().st_size)
            return response
    raise NotFound()
