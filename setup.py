from setuptools import setup, find_packages

setup(
    name="vault",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "click>=8.1.0",
        "pyperclip>=1.8.2",
    ],
    entry_points={
        "console_scripts": [
            "vault=vault.cli:cli",
        ],
    },
)
