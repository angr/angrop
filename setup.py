import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='8.19.10.30',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr==8.19.10.30',
        'pyvex==8.19.10.30',
        'claripy==8.19.10.30',
    ],
)
