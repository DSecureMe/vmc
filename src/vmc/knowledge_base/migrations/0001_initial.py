# Generated by Django 2.2.9 on 2020-01-05 21:14

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import simple_history.models
import vmc.common.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Cpe',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('vendor', models.CharField(blank=True, max_length=255, null=True)),
                ('title', models.CharField(blank=True, max_length=255, null=True)),
                ('references', models.TextField(blank=True, null=True)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Cwe',
            fields=[
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('modified_date', models.DateTimeField(auto_now=True)),
                ('id', models.CharField(max_length=16, primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('status', models.CharField(blank=True, max_length=64, null=True)),
                ('weakness_abstraction', models.CharField(blank=True, max_length=64, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('extended_description', models.TextField(blank=True, null=True)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, vmc.common.models.ModelDiffMixin),
        ),
        migrations.CreateModel(
            name='Exploit',
            fields=[
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('modified_date', models.DateTimeField(auto_now=True)),
                ('id', models.PositiveIntegerField(primary_key=True, serialize=False)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, vmc.common.models.ModelDiffMixin),
        ),
        migrations.CreateModel(
            name='HistoricalCwe',
            fields=[
                ('created_date', models.DateTimeField(blank=True, editable=False)),
                ('modified_date', models.DateTimeField(blank=True, editable=False)),
                ('id', models.CharField(db_index=True, max_length=16)),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('status', models.CharField(blank=True, max_length=64, null=True)),
                ('weakness_abstraction', models.CharField(blank=True, max_length=64, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('extended_description', models.TextField(blank=True, null=True)),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField()),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
                ('history_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'historical cwe',
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': 'history_date',
            },
            bases=(simple_history.models.HistoricalChanges, models.Model),
        ),
        migrations.CreateModel(
            name='HistoricalCve',
            fields=[
                ('id', models.CharField(db_index=True, max_length=16)),
                ('base_score_v2', models.FloatField(null=True)),
                ('base_score_v3', models.FloatField(null=True)),
                ('summary', models.TextField(blank=True, null=True)),
                ('references', models.TextField(blank=True, null=True)),
                ('published_date', models.DateTimeField(blank=True, null=True)),
                ('last_modified_date', models.DateTimeField(blank=True, null=True)),
                ('access_vector_v2', vmc.common.models.TupleValueField(blank=True, choices=[('L', 'LOCAL'), ('A', 'ADJACENT_NETWORK'), ('N', 'NETWORK')], default='L', max_length=1, null=True)),
                ('access_complexity_v2', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('M', 'MEDIUM'), ('L', 'LOW')], default='L', max_length=1, null=True)),
                ('authentication_v2', vmc.common.models.TupleValueField(blank=True, choices=[('M', 'MULTIPLE'), ('S', 'SINGLE'), ('N', 'NONE')], default='N', max_length=1, null=True)),
                ('confidentiality_impact_v2', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('P', 'PARTIAL'), ('C', 'COMPLETE')], default='N', max_length=1, null=True)),
                ('integrity_impact_v2', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('P', 'PARTIAL'), ('C', 'COMPLETE')], default='N', max_length=1, null=True)),
                ('availability_impact_v2', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('P', 'PARTIAL'), ('C', 'COMPLETE')], default='N', max_length=1, null=True)),
                ('attack_vector_v3', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NETWORK'), ('A', 'ADJACENT_NETWORK'), ('L', 'LOCAL'), ('P', 'PHYSICAL')], max_length=1, null=True)),
                ('attack_complexity_v3', vmc.common.models.TupleValueField(blank=True, choices=[('L', 'LOW'), ('H', 'HIGH')], max_length=1, null=True)),
                ('privileges_required_v3', models.CharField(blank=True, choices=[('N', 'NONE'), ('L', 'LOW'), ('H', 'HIGH')], max_length=1, null=True)),
                ('user_interaction_v3', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('R', 'REQUIRED')], max_length=1, null=True)),
                ('scope_v3', models.CharField(blank=True, choices=[('N', 'NONE'), ('R', 'REQUIRED')], max_length=1, null=True)),
                ('confidentiality_impact_v3', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('L', 'LOW'), ('N', 'NONE')], max_length=1, null=True)),
                ('integrity_impact_v3', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('L', 'LOW'), ('N', 'NONE')], max_length=1, null=True)),
                ('availability_impact_v3', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('L', 'LOW'), ('N', 'NONE')], max_length=1, null=True)),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField()),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
                ('cwe', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to='knowledge_base.Cwe')),
                ('history_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'historical cve',
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': 'history_date',
            },
            bases=(simple_history.models.HistoricalChanges, models.Model),
        ),
        migrations.CreateModel(
            name='Cve',
            fields=[
                ('id', models.CharField(max_length=16, primary_key=True, serialize=False)),
                ('base_score_v2', models.FloatField(null=True)),
                ('base_score_v3', models.FloatField(null=True)),
                ('summary', models.TextField(blank=True, null=True)),
                ('references', models.TextField(blank=True, null=True)),
                ('published_date', models.DateTimeField(blank=True, null=True)),
                ('last_modified_date', models.DateTimeField(blank=True, null=True)),
                ('access_vector_v2', vmc.common.models.TupleValueField(blank=True, choices=[('L', 'LOCAL'), ('A', 'ADJACENT_NETWORK'), ('N', 'NETWORK')], default='L', max_length=1, null=True)),
                ('access_complexity_v2', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('M', 'MEDIUM'), ('L', 'LOW')], default='L', max_length=1, null=True)),
                ('authentication_v2', vmc.common.models.TupleValueField(blank=True, choices=[('M', 'MULTIPLE'), ('S', 'SINGLE'), ('N', 'NONE')], default='N', max_length=1, null=True)),
                ('confidentiality_impact_v2', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('P', 'PARTIAL'), ('C', 'COMPLETE')], default='N', max_length=1, null=True)),
                ('integrity_impact_v2', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('P', 'PARTIAL'), ('C', 'COMPLETE')], default='N', max_length=1, null=True)),
                ('availability_impact_v2', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('P', 'PARTIAL'), ('C', 'COMPLETE')], default='N', max_length=1, null=True)),
                ('attack_vector_v3', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NETWORK'), ('A', 'ADJACENT_NETWORK'), ('L', 'LOCAL'), ('P', 'PHYSICAL')], max_length=1, null=True)),
                ('attack_complexity_v3', vmc.common.models.TupleValueField(blank=True, choices=[('L', 'LOW'), ('H', 'HIGH')], max_length=1, null=True)),
                ('privileges_required_v3', models.CharField(blank=True, choices=[('N', 'NONE'), ('L', 'LOW'), ('H', 'HIGH')], max_length=1, null=True)),
                ('user_interaction_v3', vmc.common.models.TupleValueField(blank=True, choices=[('N', 'NONE'), ('R', 'REQUIRED')], max_length=1, null=True)),
                ('scope_v3', models.CharField(blank=True, choices=[('N', 'NONE'), ('R', 'REQUIRED')], max_length=1, null=True)),
                ('confidentiality_impact_v3', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('L', 'LOW'), ('N', 'NONE')], max_length=1, null=True)),
                ('integrity_impact_v3', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('L', 'LOW'), ('N', 'NONE')], max_length=1, null=True)),
                ('availability_impact_v3', vmc.common.models.TupleValueField(blank=True, choices=[('H', 'HIGH'), ('L', 'LOW'), ('N', 'NONE')], max_length=1, null=True)),
                ('cpe', models.ManyToManyField(blank=True, to='knowledge_base.Cpe')),
                ('cwe', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='knowledge_base.Cwe')),
                ('exploits', models.ManyToManyField(blank=True, to='knowledge_base.Exploit')),
            ],
        ),
    ]
