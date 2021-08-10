from setuptools import find_packages, setup

setup(
    name='angrop',
    version='9.0.9438',
    description='The rop chain builder based off of angr',
    packages=find_packages(),
    install_requires=[
        'progressbar',
        'tqdm',
        'angr==9.0.9438',
    ],
)
