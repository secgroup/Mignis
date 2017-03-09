from setuptools import setup

setup(
    name='mignis',
    py_modules=['mignis', 'ipaddr_ext'],
    version='0.9.3',
    license='MIT',
    description='Mignis is a semantic based tool for firewall configuration',
    url='https://github.com/segroup/Mignis',
    keywords=['iptables', 'firewall', 'semantic firewall configuration', 'netfilter'],
    install_requires=['ipaddr'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: System :: Networking :: Firewalls'
    ],
    entry_points={'console_scripts': ['mignis = mignis:main']},
)
