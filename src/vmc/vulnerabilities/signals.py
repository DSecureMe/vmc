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
 */
"""

from django.dispatch import receiver

from vmc.common.elastic.signals import post_save
from vmc.assets.documents import AssetDocument
from vmc.knowledge_base.documents import CveDocument
from vmc.vulnerabilities.documents import VulnerabilityDocument


def cve_update(cve: CveDocument):
    s = VulnerabilityDocument.search().filter('term', cve__id=cve.id).extra(
        collapse={
            'field': 'asset.ip_address', "inner_hits": {
                "name": "most_recent",
                "size": 1,
                "sort": [{"modified_date": "desc"}]
            }
        }
    )
    response = s.execute()
    for vuln in response.hits:
        new_vuln = vuln.clone()
        new_vuln.cve = cve
        new_vuln.change_reason = 'CVE Updated'
        new_vuln.save(refresh=True)


def asset_update(asset: AssetDocument):
    s = VulnerabilityDocument.search().filter('term', asset__ip_address=asset.ip_address).extra(
        collapse={
            'field': 'cve.id', "inner_hits": {
                "name": "most_recent",
                "size": 1,
                "sort": [{"modified_date": "desc"}]
            }
        }
    )
    response = s.execute()
    for vuln in response.hits:
        new_vuln = vuln.clone()
        new_vuln.asset = asset
        new_vuln.change_reason = 'Asset Updated'
        new_vuln.save(refresh=True)


@receiver(post_save)
def update_cve(**kwargs):
    if isinstance(kwargs['instance'], CveDocument):
        cve_update(kwargs['instance'])

    if isinstance(kwargs['instance'], AssetDocument):
        asset_update(kwargs['instance'])
