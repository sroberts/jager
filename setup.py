from distutils.core import setup

setup(
    name="cnd-utilitybelt",
    version="0.1",
    description="Utilities to make you a CND Batman",
    url="https://github.com/yolothreat/utilitybelt",
    license="MIT",
    include_package_data=True,
    install_requires=['requests>=2.6.0',
                      'pygeoip==0.3.2',
                      'pytest>=2.6.0',
                      'pytest-cov>=1.8.1',
                      'coveralls>=0.5',
                      'pre-commit>=0.4.4'
                      ],
    package_dir={'utilitybelt': 'src'},
    packages=['utilitybelt']
)
