from distutils.core import setup

setup(
    name="jager",
    version="0.1",
    description="Pull IOCs from documents",
    url="https://github.com/yolothreat/jager",
    license="MIT",
    include_package_data=True,
    install_requires=['aspy.yaml==0.2.1',
                      'beautifulsoup4==4.3.2',
                      'cached-property==1.0.0',
                      'jsonschema==2.4.0',
                      'netaddr==0.7.12',
                      'nodeenv==0.12.3',
                      'ordereddict==1.1',
                      'pdfminer==20140328',
                      'pre-commit==0.3.6',
                      'pygeoip==0.3.2',
                      'python-magic==0.4.6',
                      'PyYAML==3.11',
                      'requests==2.4.1',
                      'simplejson==3.6.5',
                      'pytest>=2.7.0',
                      'pytest-cov>=1.8.1'
                      'cnd-utilitybelt'
                      ],
    package_dir={'jager': 'src'},
    packages=['jager']
)
