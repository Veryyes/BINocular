from setuptools import setup

setup(
    name="BINocular",
    version="1.1",
    description="Common Binary Framework",
    author="Brandon Wong",
    packages=["binocular"],
    install_requires=[
        "rich",
        "click<8.2.0",
        "typer==0.15.2",
        "pydantic",
        "networkx",
        "SQLAlchemy",
        "coloredlogs",
        "archinfo",
        "pyvex",
        "GitPython",
        "meson",
        "rzpipe",
        "tree-sitter==0.23.1",
        "tree-sitter-c==0.23.1",
        "requests",
        "IPython",
        "sphinx",
    ],
    extras_require={
        "dev": [
            "pre-commit",
            "mypy",
            "pytest",
            "sphinx",
            "sphinx_rtd_theme",
            "sphinx_mdinclude",
            "build",
            "types-networkx",
            "black",
            "types-requests",
        ]
    },
    entry_points={"console_scripts": ["binocular = binocular.run:main"]},
    package_data={"binocular": ["scripts/*"]},
)
