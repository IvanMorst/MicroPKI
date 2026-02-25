from setuptools import setup, find_packages

setup(
    name='micropki',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cryptography>=3.0',
    ],
    entry_points={
        'console_scripts': [
            'micropki = micropki.cli:main',
        ],
    },
    python_requires='>=3.8',
)