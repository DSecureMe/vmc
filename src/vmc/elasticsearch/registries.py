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

from vmc.elasticsearch import Object
from vmc.elasticsearch.models import DocumentRegistry as DBDocumentRegistry
from vmc.elasticsearch.signals import post_save
from django.conf import settings


class DocumentRegistry:

    def __init__(self):
        self.documents = dict()
        self.documents_tenant = set()

    def register_document(self, document):
        index_meta = getattr(document, 'Index')
        self.documents.update({index_meta.name: document})

        if getattr(document.Index, 'related_documents', None):
            for related in document.Index.related_documents:
                post_save.connect(self.update_related, sender=related)

        return document

    def register_new_tenant(self, tenant):
        if not DBDocumentRegistry.objects.filter(tenant__slug_name=tenant.slug_name).exists():
            for document in self.documents_tenant:
                index_name = '{}.{}.{}'.format(
                    tenant.elasticsearch_config.prefix,
                    tenant.slug_name,
                    document.Index.name
                )
                DBDocumentRegistry.objects.create(
                    index_name=index_name,
                    tenant=tenant,
                    module=document.__module__,
                    document=document.__name__
                )
                document.init(index=index_name)

    def update_related(self, sender, instance, **kwargs):
        for document in self._get_related_doc(sender):
            for field_name in document.get_fields_name():
                field_type = document._doc_type.mapping[field_name]
                if isinstance(field_type, Object) and issubclass(sender, field_type._doc_class):
                    result = document.search().filter('term', **{'{}__id'.format(field_name): instance.id}).execute()
                    for hit in result.hits:
                        setattr(hit, field_name, instance)
                        hit.save(refresh=True)

    def _get_related_doc(self, instance):
        for document in self.documents.values():
            if getattr(document.Index, 'related_documents', None):
                if instance in document.Index.related_documents:
                    yield document

    def get_documents(self):
        documents = self.documents.copy()
        for obj in DBDocumentRegistry.objects.all():
            documents.update({obj.index_name: obj.get_document()})
        return documents


registry = DocumentRegistry()
