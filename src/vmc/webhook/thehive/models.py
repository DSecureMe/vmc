from django.db import models

from vmc.common.models import BaseModel


class Case(BaseModel):
    scan_url = models.TextField(null=True)
    tenant = models.CharField(max_length=256, null=True)


class Task(BaseModel):
    scan_url = models.TextField(null=True)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, null=True)
    alert_id = models.CharField(max_length=256, null=True)
    task_id = models.CharField(max_length=256, null=True)
    document_id = models.CharField(max_length=256, null=True)
    title = models.CharField(max_length=256, null=True)
    group = models.CharField(max_length=256, null=True)
    description = models.TextField()
    source = models.CharField(max_length=256, null=True)
    ip = models.CharField(max_length=256, null=True)
    tenant = models.CharField(max_length=256, null=True)
