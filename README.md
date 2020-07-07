# P4-IPsec

This projects implements IPsec in BMv2 together with an controller based operation of IPsec. For details, please see the corresponding [paper](https://arxiv.org/abs/1907.03593).

The code in this repository is intended to work with the versions of p4c, BMv2 and PI referenced in `dependencies/user-bootstrap.sh`. More recent version are likely to break things.

## Setup
Check out the repository, install [Vagrant](https://www.vagrantup.com/), and run `vagrant up`. This will set up a VM, and mount the folder of the repository. From within the VM, run `setup.sh` to install all dependencies and the project itself.
