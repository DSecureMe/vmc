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

import os
import yaml

CFG = None
CFG_PATH = '/etc/vmc/config.yml'

try:
    with open(CFG_PATH, 'r') as ymlfile:
        CFG = yaml.safe_load(ymlfile)
except FileNotFoundError:
    pass


def get_config(key, default):
    return CFG[key] if CFG and key in CFG else default


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_config('secret_key', 'SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = get_config('debug', False)

ALLOWED_HOSTS = ['*']


INTERNAL_APPS = [
    'vmc.common',
    'vmc.assets',
    'vmc.vulnerabilities',
    'vmc.nessus',
    'vmc.knowledge_base',
]

THIRD_PARTY_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_celery_beat',
    'django_celery_results',
    'simple_history'
]

if get_config('elasticsearch.hosts', False):
    THIRD_PARTY_APPS.append('django_elasticsearch_dsl')

INSTALLED_APPS = THIRD_PARTY_APPS + INTERNAL_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'simple_history.middleware.HistoryRequestMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'vmc.config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'vmc.config.wsgi.application'

DATABASES = {'default': {}}
DATABASES['default']['ENGINE'] = get_config('database.engine', 'django.db.backends.postgresql_psycopg2')
DATABASES['default']['NAME'] = get_config('database.name', 'vmc')
DATABASES['default']['USER'] = get_config('database.user', 'postgres')
DATABASES['default']['PASSWORD'] = get_config('database.password', '')

if not get_config('database.unix_socket', ''):
    DATABASES['default']['HOST'] = get_config('database.host', 'localhost')
    DATABASES['default']['PORT'] = get_config('database.port', '')
else:
    DATABASES['default']['OPTIONS'] = {'unix_socket': get_config('database.unix_socket', '')}


AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

CELERY_BROKER_URL = 'amqp://{}:{}@{}:{}'.format(
    get_config('rabbitmq.username', 'guest'),
    get_config('rabbitmq.password', 'guest'),
    get_config('rabbitmq.host', 'localhost'),
    get_config('rabbitmq.port', 5672)
)
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ENABLE_UTC = True

CELERY_RESULT_BACKEND = 'django-db'
CELERY_CACHE_BACKEND = 'django-cache'
CELERY_BROKER_HEARTBEAT = None

if get_config('elasticsearch.hosts', False):
    ELASTICSEARCH_DSL = {
        'default': {
            'hosts': get_config('elasticsearch.hosts', 'localhost:9200'),
            'http_auth': [
                get_config('elasticsearch.user', 'elastic'),
                get_config('elasticsearch.password', 'elastic')
            ]
        },
    }

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": get_config('redis.url', 'redis://localhost:6379/1'),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient"
        },
        "KEY_PREFIX": "vmc"
    }
}
CACHE_TTL = 60 * 15

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        }
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'nessus': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'knowledge_base': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'notifications': {
            'handlers': ['console'],
            'level': 'INFO',
        }
    },
}
