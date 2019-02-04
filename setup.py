import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='8.19.2.4',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr==8.19.2.4',
        'pyvex==8.19.2.4',
        'claripy==8.19.2.4',
    ],
)
