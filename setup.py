from setuptools import find_packages, setup

setup(
    name='angrop',
    version='9.1.11752',
    description='The rop chain builder based off of angr',
    packages=find_packages(),
    install_requires=[
        'progressbar',
        'tqdm',
        'angr==9.1.11752',
    ],
)
