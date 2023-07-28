import sys

from setuptools import find_packages, setup

if sys.version_info < (3, 6):
    raise Exception("Only Python 3.6+ is supported")

from setuptools import setup

setup(
    packages=find_packages(exclude=["ez_setup", "examples", "tests", "release"]),
)
