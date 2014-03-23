from setuptools import setup
setup(name="webid-delegated-auth",
      author="Benjamin Cogrel",
      author_email="benjamin.cogrel@bcgl.fr",
      url="https://github.com/bcogrel/webid-delegated-auth",
      version="0.1",
      description="WebID delegated authentication tools (signing and checking auth URLs)",
      long_description=open('README.rst').read(),
      packages=['webid_delegated_auth'],
      include_package_data=True,
      #zip_safe = False,
      install_requires=['M2Crypto', 'python-dateutil'],
      license="MIT",
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Topic :: Software Development :: Libraries',
      ]
      )

