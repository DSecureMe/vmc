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
import netaddr
from elasticsearch_dsl import Q

from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.generics import get_object_or_404

from vmc.elasticsearch.models import Tenant
from vmc.elasticsearch.registries import registry

from vmc.vulnerabilities.documents import VulnerabilityDocument, VulnerabilityStatus
from vmc.vulnerabilities.serializers import VulnerabilityDocumentSerializer


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def search_vulnerabilities(request):
    tenant = request.GET.get('tenant', None)
    if tenant:
        tenant = get_object_or_404(Tenant, name=tenant)

    ip_address = request.GET.get('ip_address', None)
    if ip_address and netaddr.valid_ipv4(ip_address):
        index = registry.get_index_for_tenant(tenant, VulnerabilityDocument)
        result = VulnerabilityDocument.search(index=index).filter(
            Q('term', asset__ip_address=ip_address) & ~Q('match', tags=VulnerabilityStatus.FIXED)
        ).execute()[0:100]
        return Response(VulnerabilityDocumentSerializer(result, many=True).data)

    raise NotFound()
