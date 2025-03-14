from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="silentbridgelite",
    version="1.0.0",
    author="Sebastian Bicchi",
    author_email="",  # Add your email
    description="A network bridge tool for transparent network interception",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sebastianbicchi/silentbridgelite",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console :: Curses",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "python-daemon>=2.3.0",
        "scapy>=2.4.5",
        "netifaces>=0.11.0",
        "pyroute2>=0.7.3",
    ],
    entry_points={
        "console_scripts": [
            "silentbridge-cli=silentbridgelite.cli:main",
            "silentbridged=silentbridgelite.daemon:main",
        ],
    },
) 