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

from vmc.assets.documents import AssetInnerDoc, AssetDocument

from vmc.elasticsearch import Document, Integer, Keyword, Object, Float, Q
from vmc.knowledge_base.documents import CveInnerDoc, CveDocument
from vmc.elasticsearch.registries import registry

from vmc.vulnerabilities.utils import environmental_score_v2, environmental_score_v3


@registry.register_document
class VulnerabilityDocument(Document):
    id = Keyword()
    port = Integer()
    svc_name = Keyword()
    protocol = Keyword()
    description = Keyword()
    solution = Keyword()
    environmental_score_v2 = Float()
    environmental_score_v3 = Float()
    cve = Object(CveInnerDoc, include_in_parent=True)
    asset = Object(AssetInnerDoc, include_in_parent=True)
    tags = Keyword()

    class Index:
        name = 'vulnerability'
        related_documents = [CveDocument, AssetDocument]
        tenant_separation = True

    def prepare_environmental_score_v2(self):
        return environmental_score_v2(self.cve, self.asset) if self.cve.base_score_v2 else 0.0

    def prepare_environmental_score_v3(self):
        return environmental_score_v3(self.cve, self.asset) if self.cve.base_score_v3 else 0.0

    def save(self, **kwargs):
        self.environmental_score_v2 = self.prepare_environmental_score_v2()
        self.environmental_score_v3 = self.prepare_environmental_score_v3()
        return super().save(**kwargs)

    @staticmethod
    def create_or_update(vulnerabilities: dict, scanned_hosts: list, config=None) -> None:
        index = VulnerabilityDocument.get_index(config)
        all_vulnerability_docs = VulnerabilityDocument.search(index=index).filter(Q('match', tags=config.name))
        for current_vuln in all_vulnerability_docs.scan():
            vuln_id = current_vuln.id
            if vuln_id in vulnerabilities:
                if current_vuln.has_changed(vulnerabilities[vuln_id]):
                    current_vuln.update(vulnerabilities[vuln_id], refresh=True, index=index)
                del vulnerabilities[vuln_id]
            elif vuln_id not in vulnerabilities and current_vuln.asset.ip_address in scanned_hosts:
                current_vuln.tags.append('FIXED')
                current_vuln.save(refresh=True, index=index)
        for vuln in vulnerabilities.values():
            vuln.save(refresh=True, index=index)
