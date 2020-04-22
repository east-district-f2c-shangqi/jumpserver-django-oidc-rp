# -*- coding: utf-8 -*-

import codecs
from os.path import abspath
from os.path import dirname
from os.path import join
from setuptools import find_packages
from setuptools import setup

import jms_oidc_rp


def read_relative_file(filename):
    """ Returns contents of the given file, whose path is supposed relative to this module. """
    with codecs.open(join(dirname(abspath(__file__)), filename), encoding='utf-8') as f:
        return f.read()


setup(
    name='jumpserver-django-oidc-rp',
    version=jms_oidc_rp.__version__,
    author='Bai Jiangjie',
    author_email='jiangjie.bai@fit2cloud.com',
    packages=find_packages(exclude=['tests.*', 'tests']),
    include_package_data=True,
    url='https://github.com/BaiJiangJie/jumpserver-django-oidc-rp',
    license='MIT',
    description='Based on the modified django-oidc-rp adapter JumpServer OpenID Connect Relying Party (RP/Client)',
    long_description=read_relative_file('README.rst'),
    long_description_content_type="text/markdown",
    keywords='jumpserver django openidconnect oidc client rp authentication auth',
    zip_safe=False,
    install_requires=[
        'django>=1.11',
        'jsonfield2',
        'pyjwkest>=1.4',
        'requests>2.0',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
