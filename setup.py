import setuptools
from distutils.core import setup

setup(
    name='angrop',
    version='9.0.7491',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'tqdm',
        'angr==9.0.7491',
    ],
)
