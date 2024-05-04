from setuptools import setup

setup(
    name="BINocular",
    version="1.0.0",
    description="Common Binary Framework",
    author="Brandon Wong",
    packages = ["binocular"],
    install_requires = [
        'rich',
        'pydantic',
        'networkx',
        'archinfo'
        'checksec-py',
        'SQLAlchemy',
        'coloredlogs'
        'archinfo',
        'pyvex',
        'GitPython',
        'meson',
        'rzpipe',
        'pyhidra',
    ],
    # entry_points={
    #     "console_scripts": ['']
    # }
)