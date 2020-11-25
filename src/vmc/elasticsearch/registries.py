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

from enum import Enum

from django.utils.timezone import now
from django.conf import settings
from django.db.models.signals import post_delete
from elasticsearch_dsl import UpdateByQuery
from elasticsearch_dsl.connections import get_connection

from vmc.common.utils import thread_pool_executor
from vmc.elasticsearch import Object
from vmc.elasticsearch.models import DocumentRegistry as DBDocumentRegistry
from vmc.elasticsearch.signals import post_save
from vmc.elasticsearch.helpers import async_bulk


class SnapShotMode(Enum):
    DAILY = 'daily'
    MONTHLY = 'monthly'

    @classmethod
    def values(cls):
        return [snap.value for snap in cls]


class DocumentRegistry:

    def __init__(self):
        self.documents = dict()
        self.documents_tenant = set()
        self.related_documents = set()
        post_delete.connect(self.remove_index, DBDocumentRegistry)

    @staticmethod
    def remove_index(**kwargs):
        instance = kwargs['instance']
        client = get_connection()
        client.indices.delete(index=instance.index_name, ignore=404)

    def register_document(self, document):
        index_meta = getattr(document, 'Index')
        self.documents.update({index_meta.name: document})

        for value in SnapShotMode.values():
            snap_index = '{}.{}'.format(index_meta.name, value)
            self.documents.update({snap_index: document})

        if getattr(document.Index, 'tenant_separation', False):
            self.documents_tenant.add(document)

        if getattr(document.Index, 'related_documents', None):
            for related in document.Index.related_documents:
                if related not in self.related_documents:
                    post_save.connect(self.update_related, sender=related)
                    self.related_documents.add(related)

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

                for snap_index in SnapShotMode:
                    document.init(index='{}.{}'.format(index_name, snap_index.value))

    def update_related(self, sender, new_version, old_version, **kwargs):
        if old_version:
            updates = []
            for document in self._get_related_doc(sender):
                for field_name in document.get_fields_name():
                    field_type = document._doc_type.mapping[field_name]

                    if isinstance(field_type, Object) and issubclass(sender, field_type._doc_class):

                        for index in self._get_indexes(new_version, document):
                            search = document.search(index=index).filter(
                                'term', **{F'{field_name}__id': old_version.id})
                            count = search.count()

                            if count > 0:

                                has_related_documents = getattr(document, 'related_documents', False)
                                if not has_related_documents:
                                    thread_pool_executor.submit(
                                        self._update_by_query,
                                        index if index else document.Index.name,
                                        field_name,
                                        old_version,
                                        new_version
                                    )
                                else:

                                    if count > 10000:
                                        result = search.scan()
                                    elif count > 0:
                                        result = search[0:count].execute()
                                    else:
                                        result = []

                                    for hit in result:
                                        setattr(hit, field_name, new_version)
                                        updates.append(hit.save(index=index, weak=True).to_dict(include_meta=True))

                                    if len(updates) > 500:
                                        async_bulk(updates)
                                        updates = []

            async_bulk(updates)

    @staticmethod
    def _update_by_query(index, field_name, old_version, new_version):
        ubq = UpdateByQuery(using=get_connection(), index=index).filter(
            'term', **{F'{field_name}__id': old_version.id}
        ).script(source=F'ctx._source.{field_name} = params.new_value; ctx._source.modified_date = params.new_date',
                 params={
                     'new_value': new_version.to_dict(),
                     'new_date': now()
                 })
        refresh = getattr(settings, 'TEST', False)
        ubq.params(refresh=refresh, conflicts='proceed').execute()

    def _get_indexes(self, instance, receiver):
        if getattr(instance.Index, 'tenant_separation', False):
            try:
                index_data = DBDocumentRegistry.objects.get(index_name=instance._get_index())
                return [DBDocumentRegistry.objects.values_list('index_name', flat=True).get(
                    tenant=index_data.tenant,
                    module=receiver.__module__,
                    document=receiver.__name__
                )]
            except DBDocumentRegistry.DoesNotExist:
                return [None]
        return [index for index in self.get_documents()]

    def _get_related_doc(self, instance):
        for document in self.documents.values():
            if getattr(document.Index, 'related_documents', None):
                if instance in document.Index.related_documents:
                    yield document

    def get_documents(self):
        documents = self.documents.copy()

        for obj in DBDocumentRegistry.objects.all():
            documents.update({obj.index_name: obj.get_document()})

            for value in SnapShotMode.values():
                snap_index = F'{obj.index_name}.{value}'
                documents.update({snap_index: obj.get_document()})

        return documents

    @staticmethod
    def get_index_for_tenant(tenant, document):
        if tenant:
            return DBDocumentRegistry.objects.values_list('index_name', flat=True).get(
                tenant=tenant,
                module=document.__module__,
                document=document.__name__
            )
        return document.Index.name


registry = DocumentRegistry()
