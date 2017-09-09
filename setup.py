import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='7.7.9.8',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr',
        'pyvex',
        'claripy',
    ],
)
