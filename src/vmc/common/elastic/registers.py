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

from collections import defaultdict


class DocumentRegistry:

    def __init__(self):
        self.documents = defaultdict()

    def register_document(self, document):
        index_meta = getattr(document, 'Index')
        self.documents.update({index_meta.name: document})
        return document

    def get_documents(self):
        return self.documents.values()


registry = DocumentRegistry()
