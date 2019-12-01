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

from django.db import models
from simple_history.models import HistoricalRecords

from vmc.common.models import BaseModel, TupleValueField

from vmc.knowledge_base import metrics


class Cwe(BaseModel):
    id = models.CharField(max_length=16, primary_key=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=64, null=True, blank=True)
    weakness_abstraction = models.CharField(max_length=64, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    extended_description = models.TextField(null=True, blank=True)
    history = HistoricalRecords()

    def __str__(self):
        return self.id


class Cpe(models.Model):
    name = models.CharField(max_length=255, primary_key=True)
    vendor = models.CharField(max_length=255, blank=True, null=True)
    title = models.CharField(max_length=255, blank=True, null=True)
    references = models.TextField(null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.vendor and self.title:
            return '{} {}'.format(self.vendor, self.title)
        return self.name


class Exploit(BaseModel):
    id = models.PositiveIntegerField(primary_key=True)


class Cve(models.Model):
    id = models.CharField(max_length=16, primary_key=True)
    base_score_v2 = models.FloatField(null=True)
    base_score_v3 = models.FloatField(null=True)
    summary = models.TextField(null=True, blank=True)
    references = models.TextField(null=True, blank=True)
    cwe = models.ForeignKey(Cwe, null=True, blank=True, on_delete=models.DO_NOTHING)
    cpe = models.ManyToManyField(Cpe)
    published_date = models.DateTimeField(null=True, blank=True)
    last_modified_date = models.DateTimeField(null=True, blank=True)
    access_vector_v2 = TupleValueField(
        choices=metrics.AccessVectorV2.choices(),
        default=metrics.AccessVectorV2.LOCAL.value,
        choice_type=metrics.AccessVectorV2,
        max_length=1
    )
    access_complexity_v2 = TupleValueField(
        choices=metrics.AccessComplexityV2.choices(),
        default=metrics.AccessComplexityV2.LOW.value,
        choice_type=metrics.AccessComplexityV2,
        max_length=1
    )
    authentication_v2 = TupleValueField(
        choices=metrics.AuthenticationV2.choices(),
        default=metrics.AuthenticationV2.NONE.value,
        choice_type=metrics.AuthenticationV2,
        max_length=1
    )
    confidentiality_impact_v2 = TupleValueField(
        choices=metrics.ImpactV2.choices(),
        default=metrics.ImpactV2.NONE.value,
        choice_type=metrics.ImpactV2,
        max_length=1
    )
    integrity_impact_v2 = TupleValueField(
        choices=metrics.ImpactV2.choices(),
        default=metrics.ImpactV2.NONE.value,
        choice_type=metrics.ImpactV2,
        max_length=1
    )
    availability_impact_v2 = TupleValueField(
        choices=metrics.ImpactV2.choices(),
        default=metrics.ImpactV2.NONE.value,
        choice_type=metrics.ImpactV2,
        max_length=1
    )
    attack_vector_v3 = TupleValueField(
        choices=metrics.AttackVectorV3.choices(),
        choice_type=metrics.AttackVectorV3,
        max_length=1,
        null=True
    )
    attack_complexity_v3 = TupleValueField(
        choices=metrics.AttackComplexityV3.choices(),
        choice_type=metrics.AttackComplexityV3,
        max_length=1,
        null=True
    )
    privileges_required_v3 = models.CharField(
        choices=metrics.PrivilegesRequiredV3.choices(),
        max_length=1,
        null=True
    )
    user_interaction_v3 = TupleValueField(
        choices=metrics.UserInteractionV3.choices(),
        choice_type=metrics.UserInteractionV3,
        max_length=1,
        null=True
    )
    scope_v3 = models.CharField(
        choices=metrics.UserInteractionV3.choices(),
        max_length=1,
        null=True
    )
    confidentiality_impact_v3 = TupleValueField(
        choices=metrics.ImpactV3.choices(),
        choice_type=metrics.ImpactV3,
        max_length=1,
        null=True
    )
    integrity_impact_v3 = TupleValueField(
        choices=metrics.ImpactV3.choices(),
        choice_type=metrics.ImpactV3,
        max_length=1,
        null=True
    )
    availability_impact_v3 = TupleValueField(
        choices=metrics.ImpactV3.choices(),
        choice_type=metrics.ImpactV3,
        max_length=1,
        null=True
    )
    exploits = models.ManyToManyField(Exploit)
    history = HistoricalRecords()

    def get_privileges_required_v3_value(self) -> float:
        scope = metrics.ScopeV3(self.scope_v3)
        return float(metrics.PrivilegesRequiredV3(self.privileges_required_v3).value_with_scope(scope))

    def __str__(self):
        return self.id
