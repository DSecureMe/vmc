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

from django.test import TestCase

from vmc.assets.models import Port, Asset, Impact


class PortTest(TestCase):
    fixtures = ['assets.json']

    @classmethod
    def setUpTestData(cls):
        cls.uut = Port.objects.get(pk=1)

    def test_str_call(self):
        self.assertEqual(self.uut.__str__(), "22")


class AssetTest(TestCase):
    fixtures = ['assets.json']

    @classmethod
    def setUpTestData(cls):
        cls.uut = Asset.objects.get(pk=1)

    def test_call(self):
        self.assertEqual(self.uut.__str__(), "10.10.10.1")
        self.assertEqual(self.uut.confidentiality_requirement, Impact.NOT_DEFINED.value)
        self.assertEqual(self.uut.get_confidentiality_requirement_display(), Impact.NOT_DEFINED.name)
        self.assertEqual(self.uut.get_confidentiality_requirement_value(), Impact.NOT_DEFINED.float)

        self.assertEqual(self.uut.integrity_requirement, Impact.NOT_DEFINED.value)
        self.assertEqual(self.uut.get_integrity_requirement_display(), Impact.NOT_DEFINED.name)
        self.assertEqual(self.uut.get_integrity_requirement_value(), Impact.NOT_DEFINED.float)

        self.assertEqual(self.uut.availability_requirement, Impact.NOT_DEFINED.value)
        self.assertEqual(self.uut.get_availability_requirement_display(), Impact.NOT_DEFINED.name)
        self.assertEqual(self.uut.get_availability_requirement_value(), Impact.NOT_DEFINED.float)
