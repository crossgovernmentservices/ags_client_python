from functools import reduce
from setuptools import setup, find_packages

with open('ags/__init__.py', 'r') as f:
    version = reduce(
        lambda a, l: l.startswith('__version__') and l[15:-2] or a, f, '')

with open('README.rst', 'r') as f:
    readme = f.read()

setup(
    name='ags_client',
    version=version,
    packages=find_packages(),
    description=('Client library for accessing GaaP services'),
    long_description=readme,
    author='Government Digital Service',
    author_email='andy.driver@digital.cabinet-office.gov.uk',
    maintainer='Andy Driver',
    maintainer_email='andy.driver@digital.cabinet-office.gov.uk',
    keywords=['python', 'gds', 'govuk'],
    platforms=['any'],
    url='https://github.com/crossgovernmentservices/ags_client_python',
    license='LICENSE',
    install_requires=[
        'requests>=2.7,<3', 
        'python-jose>=1.3.2',
        'cached-property>=1.3.0',
        'beaker>=1.8.1',
        'cryptography>=1.5.2'],
    test_suite="tests",
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules'])
