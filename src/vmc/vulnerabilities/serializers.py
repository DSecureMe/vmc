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
from rest_framework import serializers


class VulnerabilityDocumentSerializer(serializers.Serializer):
    cve = serializers.SerializerMethodField()
    summary = serializers.SerializerMethodField()
    base_score_v2 = serializers.SerializerMethodField()
    base_score_v3 = serializers.SerializerMethodField()
    port = serializers.IntegerField()
    svc_name = serializers.CharField()
    protocol = serializers.CharField()
    description = serializers.CharField()
    environmental_score_v2 = serializers.FloatField()
    environmental_score_vector_v2 = serializers.CharField()
    environmental_score_v3 = serializers.FloatField()
    environmental_score_vector_v3 = serializers.CharField()
    tags = serializers.ListField()
    source = serializers.CharField()
    created_date = serializers.DateTimeField()
    modified_date = serializers.DateTimeField()

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        raise NotImplementedError()

    @staticmethod
    def get_cve(obj):
        return obj.cve.id

    @staticmethod
    def get_summary(obj):
        return obj.cve.summary

    @staticmethod
    def get_base_score_v2(obj):
        return obj.cve.base_score_v2

    @staticmethod
    def get_base_score_v3(obj):
        return obj.cve.base_score_v3
