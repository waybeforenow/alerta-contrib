from setuptools import setup, find_packages

version = "5.5.1"

setup(
    name="alerta-zenduty",
    version=version,
    description="Zenduty plugin for Slack",
    url="https://github.com/alerta/alerta-contrib",
    license="MIT",
    author="wbn",
    author_email="wbn@striated.space",
    packages=find_packages(),
    py_modules=["alerta_zenduty"],
    install_requires=["requests"],
    include_package_data=True,
    zip_safe=True,
    entry_points={"alerta.plugins": ["zenduty = alerta_zenduty:ServiceIntegration"]},
)