from setuptools import setup, find_packages

import sys
import os.path
sys.path.insert(0, os.path.abspath('.'))
from panstix import __version__

with open('requirements.txt') as f:
    _requirements = [dep for dep in f.read().splitlines() if not dep.startswith('git+')]

with open('README.md') as f:
    _long_description = f.read()

setup(
    name='pan-stix',
    version=__version__,
    url='https://github.com/PaloAltoNetworks-BD/pan-stix',
    license='ISC',
    author='Palo Alto Networks',
    author_email='techbizdev@paloaltonetworks.com',
    description='Tools for converting Palo Alto Networks threats to STIX',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: Internet'
    ],
    long_description=_long_description,
    packages=find_packages(),
    install_requires=_requirements,
    scripts=[
        'wildfire-to-stix.py'
    ]
)
