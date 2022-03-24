from setuptools import find_packages, setup

setup(
    name='angrop',
    version='9.2.0.dev0',
    description='The rop chain builder based off of angr',
    packages=find_packages(),
    install_requires=[
        'tqdm',
        'angr==9.2.0.dev0',
    ],
)
