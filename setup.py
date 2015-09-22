from distutils.core import setup

setup(
    name='angrop',
    version='1.0',
    description='The rop chain builder based off of angr',
    packages=['angrop'],
    install_requires=[
        'progressbar',
        'angr',
        'pyvex',
        'claripy',
        'simuvex',
    ],
)
