from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(
    name='mignis',
    py_modules=['mignis', 'ipaddr_ext'],
    version='0.9.6',
    license='MIT',
    description='Mignis is a semantic based tool for firewall configuration with NAT reflection support',
    long_description=readme(),
    url='https://github.com/segroup/Mignis',
    keywords=['iptables', 'firewall', 'semantic firewall configuration', 'netfilter', 'nat reflection', 'hairpinning'],
    python_requires='>=3.6',
    install_requires=[],  # No external dependencies - uses stdlib ipaddress
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Networking :: Firewalls'
    ],
    entry_points={'console_scripts': ['mignis = mignis:main']},
)
