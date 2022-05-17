# Build and Release Status

# Installation
## Debian/Ubuntu
The latest version of the keysinuse package is hosted on packages.microsoft.com.
1. Add azurecore repo to the sources list  
    - Debian  
  `echo 'deb [arch=amd64] http://packages.microsoft.com/repos/azurecore/ trusty main' | sudo tee -a /etc/apt/sources.list.d/azure.list`
    - Ubuntu 18.04  
  `echo 'deb [arch=amd64] http://packages.microsoft.com/repos/azurecore/ bionic main' | sudo tee -a /etc/apt/sources.list.d/azure.list`
    - Ubuntu 20.04  
  `echo 'deb [arch=amd64] http://packages.microsoft.com/repos/azurecore/ focal main' | sudo tee -a /etc/apt/sources.list.d/azure.list`

2. Add repo GPG key
    - Download key  
        `wget https://packages.microsoft.com/keys/microsoft.asc`  
        `wget https://packages.microsoft.com/keys/msopentech.asc`  
        or  
        `curl https://packages.microsoft.com/keys/microsoft.asc`  
        `curl https://packages.microsoft.com/keys/msopentech.asc`
    - Add downloaded key  
        `apt-key add microsoft.asc`  
        `apt-key add msopentech.asc`

4. Update package list  
`apt-get update `

5. Install the latest version of the keys-in-use and azsecpack packages  
`apt-get install -y keysinsue`

## RHEL/Mariner

1. Create /etc/yum.repos.d/azurecoretest.repo with contents:
```dosini
[packages-microsoft-com-azurecore]
name=packages-microsoft-com-azurecore
baseurl=https://packages.microsoft.com/yumrepos/azurecore/
enabled=1
gpgcheck=0
```

2. Install the latest version of the keys-in-use
`sudo yum install keysinuse`

# Manual Setup
1. Create the folder `/var/log/keysinuse` with universal read-write permissions
2. Place [keysinuse.so](./bin/keysinuse.so) on the host machine where if can be accessed by any application linking to OpenSSL. For example:
    -  `/usr/local/lib`
    - OpenSSL engines directory (`openssl version -e`)
3. Create a new *.cnf file with the following lines `/usr/lib/ssl/openssl.cnf`
```dosini
openssl_conf = openssl_init

[ openssl_init ]
engines = engine_section

[ engine_section ]
keysinuse = keysinuse_section

[ keysinuse_section ]
engine_id = keysinuse
dynamic_path = <Path to engine SO> ; e.g. /usr/local/lib/keysinuse.so
default_algorithms = RSA,EC
init = 1
```
4. Add `.include <path to config from 3>` to `/usr/lib/ssl/openssl.cnf`
5. Restart/Reload any applications with OpenSSL loaded

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

# Additional Documents
- [Building the engine](./docs/build.md)
- [Testing the engine](./docs/test.md)
- [Troubleshooting the engine](./docs/troubleshooting.md)