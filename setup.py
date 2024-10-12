from setuptools import setup

setup(
    name="BINocular",
    version="1.1",
    description="Common Binary Framework",
    author="Brandon Wong",
    packages = ["binocular"],
    install_requires = [
        'rich',
        'typer',
        'pydantic',
        'networkx',
        'checksec-py>=0.7.4',
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
        'requests',
        'IPython',
        'sphinx'
    ],
    extra_require = {
        'dev': ['pytest', 'sphinx', 'sphinx_rtd_theme', 'sphinx_mdinclude', 'build']
    },
    entry_points={
        "console_scripts": ['binocular = binocular.run:main']
    }
)
