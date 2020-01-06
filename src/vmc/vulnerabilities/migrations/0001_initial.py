# Generated by Django 2.2.9 on 2020-01-05 21:14

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import simple_history.models
import vmc.common.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('knowledge_base', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('assets', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('modified_date', models.DateTimeField(auto_now=True)),
                ('description', models.TextField()),
                ('solution', models.TextField(blank=True, null=True)),
                ('exploit_available', models.BooleanField(default=False)),
                ('asset', models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='assets.Asset')),
                ('cve', models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='knowledge_base.Cve')),
                ('port', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='assets.Port')),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, vmc.common.models.ModelDiffMixin),
        ),
        migrations.CreateModel(
            name='HistoricalVulnerability',
            fields=[
                ('id', models.IntegerField(auto_created=True, blank=True, db_index=True, verbose_name='ID')),
                ('created_date', models.DateTimeField(blank=True, editable=False)),
                ('modified_date', models.DateTimeField(blank=True, editable=False)),
                ('description', models.TextField()),
                ('solution', models.TextField(blank=True, null=True)),
                ('exploit_available', models.BooleanField(default=False)),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField()),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
                ('asset', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to='assets.Asset')),
                ('cve', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to='knowledge_base.Cve')),
                ('history_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('port', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to='assets.Port')),
            ],
            options={
                'verbose_name': 'historical vulnerability',
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': 'history_date',
            },
            bases=(simple_history.models.HistoricalChanges, models.Model),
        ),
    ]
