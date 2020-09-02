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

from rest_framework.generics import get_object_or_404
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from pathlib import Path

from vmc.scanners.models import Scan


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def download_scan(request, scan_id):
    if not re.match(r"[a-f0-9]{64}", scan_id):
        raise NotFound

    if scan_id:
        scan = get_object_or_404(Scan, file_id=scan_id)
        file_path = Path(scan.file)
        with file_path.open(mode="rb") as file_handle:
            response = Response(file_handle, content_type="text/xml")
            response["Content-Disposition"] = F"scan_file; filename={file_path.name}"
            response["Content-Length"] = str(file_path.stat().st_size)
    raise NotFound()
