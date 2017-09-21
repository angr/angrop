import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='7.7.9.21',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr>=7.7.9.21',
        'pyvex>=7.7.9.14',
        'claripy>=7.7.9.14',
    ],
)
