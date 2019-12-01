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
import sys
import os
from setuptools import setup, find_packages

assert sys.version_info >= (3, 3), 'Python 3.3+ required.'

THIS_DIRECTORY = os.path.abspath(os.path.dirname(__file__))


def read(file_name):
    return open(os.path.join(THIS_DIRECTORY, file_name), encoding='utf-8').read()


def install_requires():
    return read('requirements.txt').splitlines()


def tests_require():
    return read('test_requirements.txt').splitlines()


setup(
    name='vmcenter',
    version=read('VERSION.txt'),
    author='DSecure.me',
    author_email='vmc-support@dsecure.me',
    description="Vulnerability Management Center",
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    url='https://github.com/DSecureMe/vmc',
    platforms=['any'],
    license='Apache Software License v2.0',
    packages=find_packages('src'),
    keywords='',
    include_package_data=True,
    package_dir={'': 'src'},
    package_data={
        '': ['*.txt', '*.md'],
    },
    data_files=[
        ('/etc/vmc/', ['config/config.yml'])
    ],
    install_requires=install_requires(),
    tests_require=tests_require(),
    entry_points={
        'console_scripts': [
            'vmc = vmc.__main__:main'
        ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
    ]
)