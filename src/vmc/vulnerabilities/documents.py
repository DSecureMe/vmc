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
from elasticsearch_dsl import Q

from vmc.assets.documents import AssetInnerDoc, AssetDocument

from vmc.elasticsearch import Document, Keyword, Object, Float, ListField
from vmc.elasticsearch.registries import registry
from vmc.elasticsearch.helpers import async_bulk
from vmc.knowledge_base.documents import CveInnerDoc, CveDocument


class VulnerabilityStatus:
    FIXED = 'FIXED'


@registry.register_document
class VulnerabilityDocument(Document):
    id = Keyword()
    port = Keyword()
    svc_name = Keyword()
    protocol = Keyword()
    description = Keyword()
    solution = Keyword()
    environmental_score_v2 = Float()
    environmental_score_vector_v2 = Keyword()
    environmental_score_v3 = Float()
    environmental_score_vector_v3 = Keyword()
    cve = Object(CveInnerDoc, include_in_parent=True)
    asset = Object(AssetInnerDoc, include_in_parent=True)
    tags = ListField()
    source = Keyword()

    class Index:
        name = 'vulnerability'
        related_documents = [CveDocument, AssetDocument]
        tenant_separation = True

    @staticmethod
    def create_or_update(vulnerabilities: dict, scanned_hosts: list, config=None) -> None:
        index = VulnerabilityDocument.get_index(config)
        docs = []
        all_vulnerability_docs = VulnerabilityDocument.search(index=index).filter(
            ~Q('match', tags=VulnerabilityStatus.FIXED)
        )
        for current_vuln in all_vulnerability_docs.scan():
            vuln_id = current_vuln.id
            if vuln_id in vulnerabilities:
                if current_vuln.has_changed(vulnerabilities[vuln_id]):
                    c = current_vuln.update(vulnerabilities[vuln_id], index=index, weak=True)
                    docs.append(c.to_dict(include_meta=True))
                del vulnerabilities[vuln_id]
            elif vuln_id not in vulnerabilities and current_vuln.asset.ip_address in scanned_hosts:
                current_vuln.tags.append(VulnerabilityStatus.FIXED)
                c = current_vuln.save(index=index, weak=True)
                docs.append(c.to_dict(include_meta=True))

            if len(docs) > 500:
                async_bulk(docs, index=index)
                docs = []

        docs.extend(list(map(lambda x: x.save(weak=True).to_dict(), vulnerabilities.values())))
        async_bulk(docs, index=index)
