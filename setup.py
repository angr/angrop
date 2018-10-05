import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='8.18.10.5',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr==8.18.10.5',
        'pyvex==8.18.10.5',
        'claripy==8.18.10.5',
    ],
)
