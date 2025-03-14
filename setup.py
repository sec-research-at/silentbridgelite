from setuptools import setup, find_packages

setup(
    name="silentbridgelite",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.4.5",
        "netifaces>=0.11.0",
        "nanpy",
        'windows-curses; platform_system == "Windows"',
    ],
    entry_points={
        'console_scripts': [
            'silentbridge-cli=silentbridgelite.cli.cli:main',
            'silentbridged=silentbridgelite.daemon.daemon:main',
        ],
    },
    author="Sebastian Bicchi",
    description="A lightweight version of SilentBridge for network analysis",
    long_description=open("readme.md").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.7",
) 