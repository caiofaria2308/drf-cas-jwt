import sys

from setuptools import find_packages, setup

if sys.version_info < (3, 6):
    raise Exception("Only Python 3.6+ is supported")

from setuptools import setup

setup(
    name="drf_cas_jwt",
    version="0.1.0",
    author="Caio de Faria",
    author_email="caiofaria2308@gmail.com",
    url="https://github.com/caiofaria2308/drf-cas-jwt",
    packages=find_packages(exclude=["ez_setup", "examples", "tests", "release"]),
    install_requires=[
        "Django~=2.0",
        "confluent-kafka==1.9.2",
        "django-cas-ng~=4.9.9",
        "djangorestframework-simplejwt~=4.9.9",
        "django-user-agents~=0.9.9",
        "pyyaml~=5.9.9",
        "ua-parser~=0.9.9",
        "user-agents~=2.9.9",
    ],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
