"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# To use a consistent encoding
from codecs import open
from os import path

# Always prefer setuptools over distutils
from setuptools import setup

# Converting the README from markdown to rst
try:
    import pypandoc

    long_description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
    long_description = open('README.md').read()

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
# with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
#    long_description = f.read()

setup(
    name='mistertango',
    version='0.1',

    description='Basic Mistertango API client',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/RomanMelnyk113/mistertango-python',

    # Author details
    author='Roman Melnyk',
    author_email='roman.melnyk20071992@gmail.com',

    # Choose your license
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],

    keywords='mistertango payment python',
    packages=['mistertango'],

    install_requires=['requests'],

    python_requires='>=3.5',

    extras_require={
        'dev': ['pytest'],
    },
)
