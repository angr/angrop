import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='7.8.8.1',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr>=7.8.8.1',
        'pyvex>=7.8.8.1',
        'claripy>=7.8.8.1',
    ],
)
