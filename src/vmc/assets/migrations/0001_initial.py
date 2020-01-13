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
            name='Asset',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('modified_date', models.DateTimeField(auto_now=True)),
                ('ip_address', models.CharField(max_length=16)),
                ('cmdb_id', models.PositiveIntegerField(blank=True, null=True)),
                ('mac_address', models.CharField(blank=True, max_length=17)),
                ('os', models.CharField(blank=True, max_length=128)),
                ('business_owner', models.CharField(blank=True, max_length=128, null=True)),
                ('technical_owner', models.CharField(blank=True, max_length=128, null=True)),
                ('hostname', models.CharField(max_length=128)),
                ('confidentiality_requirement', vmc.common.models.TupleValueField(choices=[('L', 'LOW'), ('M', 'MEDIUM'), ('H', 'HIGH'), ('N', 'NOT_DEFINED')], default='N', max_length=1)),
                ('integrity_requirement', vmc.common.models.TupleValueField(choices=[('L', 'LOW'), ('M', 'MEDIUM'), ('H', 'HIGH'), ('N', 'NOT_DEFINED')], default='N', max_length=1)),
                ('availability_requirement', vmc.common.models.TupleValueField(choices=[('L', 'LOW'), ('M', 'MEDIUM'), ('H', 'HIGH'), ('N', 'NOT_DEFINED')], default='N', max_length=1)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, vmc.common.models.ModelDiffMixin),
        ),
        migrations.CreateModel(
            name='HistoricalAsset',
            fields=[
                ('id', models.IntegerField(auto_created=True, blank=True, db_index=True, verbose_name='ID')),
                ('created_date', models.DateTimeField(blank=True, editable=False)),
                ('modified_date', models.DateTimeField(blank=True, editable=False)),
                ('ip_address', models.CharField(max_length=16)),
                ('cmdb_id', models.PositiveIntegerField(blank=True, null=True)),
                ('mac_address', models.CharField(blank=True, max_length=17)),
                ('os', models.CharField(blank=True, max_length=128)),
                ('business_owner', models.CharField(blank=True, max_length=128, null=True)),
                ('technical_owner', models.CharField(blank=True, max_length=128, null=True)),
                ('hostname', models.CharField(max_length=128)),
                ('confidentiality_requirement', vmc.common.models.TupleValueField(choices=[('L', 'LOW'), ('M', 'MEDIUM'), ('H', 'HIGH'), ('N', 'NOT_DEFINED')], default='N', max_length=1)),
                ('integrity_requirement', vmc.common.models.TupleValueField(choices=[('L', 'LOW'), ('M', 'MEDIUM'), ('H', 'HIGH'), ('N', 'NOT_DEFINED')], default='N', max_length=1)),
                ('availability_requirement', vmc.common.models.TupleValueField(choices=[('L', 'LOW'), ('M', 'MEDIUM'), ('H', 'HIGH'), ('N', 'NOT_DEFINED')], default='N', max_length=1)),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField()),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
                ('history_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'historical asset',
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': 'history_date',
            },
            bases=(simple_history.models.HistoricalChanges, models.Model),
        ),
    ]
