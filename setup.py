from setuptools import setup, find_packages

setup(
    name='micropki',
    version='0.2.0',  # Updated for Sprint 2
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