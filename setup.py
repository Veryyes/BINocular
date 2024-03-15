from setuptools import setup

setup(
    name="BINocular",
    version="1.0.0",
    description="Common Binary Framework",
    author="Brandon Wong",
    packages = ["binocular"],
    install_requires = [
        'rich',
        'pydantic'
    ],
    # entry_points={
    #     "console_scripts": ['']
    # }
)