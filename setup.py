import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pycrowdsec",
    version="0.0.1",
    author="CrowdSec",
    description="CrowdSec API client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sbs2001/pycrowdsec",
    project_urls={
        "Bug Tracker": "https://github.com/sbs2001/pycrowdsec/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)