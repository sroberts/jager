from setuptools import setup, find_packages


setup(
    name="cnd-utilitybelt",
    version="0.1",
    description="Utilities to make you a CND Batman",
    url="https://github.com/yolothreat/utilitybelt",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=['requests', 'GeoIP']
)
