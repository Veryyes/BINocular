from setuptools import setup

setup(
    name="BINocular",
    version="1.0.0",
    description="Common Binary Framework",
    author="Brandon Wong",
    packages = ["binocular"],
    install_requires = [
        'rich',
        'typer',
        'pydantic',
        'checksec.py',
        'networkx',
        'checksec-py',
        'SQLAlchemy',
        'coloredlogs',
        'archinfo',
        'pyvex',
        'GitPython',
        'meson',
        'rzpipe',
        'pyhidra',
        'tree-sitter',
        'tree-sitter-c',
        'requests'

    ],
    extra_require = {
        'dev': ['pytest', 'IPython']
    },
    entry_points={
        "console_scripts": ['binocular = binocular.run:main']
    }
)
