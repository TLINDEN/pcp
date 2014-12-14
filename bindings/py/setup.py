import os 
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "pypcp",
    version = "0.2.3",
    author = "Thomas von Dein",
    author_email = "tlinden@cpan.org",
    description = ("python libpcp wrapper"),
    license = "GPL",
    keywords = "cryptography API NaCl libpcp",
    url = "https://github.com/tlinden/pcp/bindings/py",
    packages = find_packages(),
    #long_description=read('README.md'),
    classifiers = ["Development Status :: 4 - Beta",
                   "License :: OSI Approved :: GPL",
                   "Topic :: Security :: Cryptography",
                   "Topic :: Security",
                   ],
)
