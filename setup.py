import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='7.8.6.16',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr>=7.8.6.16',
        'pyvex>=7.8.6.16',
        'claripy>=7.8.6.16',
    ],
)
