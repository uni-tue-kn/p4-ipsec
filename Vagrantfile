Vagrant.configure(2) do |config|
  config.vagrant.plugins = "vagrant-reload"

  config.vm.box = "ubuntu/xenial64"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "P4-IPsec Testbed" + Time.now.strftime(" %Y-%m-%d")
    vb.gui = false
    vb.memory = 6048
    vb.cpus = 3
    vb.customize ["modifyvm", :id, "--vram", "32"]
  end

  config.vm.synced_folder '.', '/vagrant'
  config.ssh.forward_x11 = true
  config.vm.hostname = "p4"
end
