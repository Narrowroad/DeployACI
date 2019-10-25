import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="deployaci-wyko.terhaar",
    version="0.0.1",
    author="Wyko ter Haar",
    author_email="wyko.terhaar@sbmoffshore.com",
    description="Creates a new ACI network environment for applications deployed in the SBM Amsterdam datacenter.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="mcdevtfs2013:8080/tfs/SBM/Network%20Automation",
    install_requires=[
        'pytest',
        'urllib3',
        'orionsdk>=0.0.6',
        'PyForms-GUI>=4.0.14',
        'pyforms',
      ],
    dependency_links=['https://github.com/datacenter/pyaci/archive/master.zip'],
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 3 - Alpha",
        "Operating System :: OS Independent",
        "License :: Other/Proprietary License",
    ],
)