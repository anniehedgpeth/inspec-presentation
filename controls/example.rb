title '3 - Secure Boot Settings'

control '3.1' do
  impact 0.1
  title '3.1 Set User/Group Owner on bootloader config (Scored)'
  desc 'Set the owner and group of your boot loaders config file to the root user. These instructions default to GRUB stored at /boot/grub/grub.cfg.'
  describe file('/boot/grub/grub.cfg') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
  end
end

control '3.2' do
  impact 0.1
  title '3.2 Set Permissions on bootloader config (Scored)'
  desc 'Set permission on the your boot loaders config file to read and write for root only.'
  describe file('/boot/grub/grub.cfg') do
    it { should exist }
    its("gid") { should cmp 0 }
    its("uid") { should cmp 0 }
    it { should be_owned_by 'root' }
    it { should be_readable.by "owner" }
    it { should be_writable.by "owner" }
    it { should be_executable.by "owner" }
    it { should_not be_executable.by "group" }
    it { should_not be_readable.by "group" }
    it { should_not be_writable.by "group" }
    it { should_not be_executable.by "other" }
    it { should_not be_readable.by "other" }
    it { should_not be_writable.by "other" }
  end
end

# encoding: utf-8
# copyright: 2016, Annie Hedgpeth
# license: All rights reserved

title '4 - Additional Process Hardening'

control '4.1' do
  impact 0.1
  title '4.1 Restrict Core Dumps (Scored)'
  desc 'A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.'
  describe limits_conf('/etc/security/limits.conf') do
    its('*') { should include ['hard', 'core', '0'] }
  end
  describe file('/etc/sysctl.conf') do
    its('content') { should match /^\s*fs.suid_dumpable = 0\s*(#.*)?$/ }
  end

  describe package('apport') do
    it { should_not be_installed }
  end
  describe package('whoopsie') do
    it { should_not be_installed }
  end
end

control '4.3' do
  impact 0.1
  title '4.3 Enable Randomized Virtual Memory Region Placement'
  desc 'Set the system flag to force randomized virtual memory region placement.'
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

control '4.4' do
  impact 0.1
  title '4.4 Disable Prelink'
  desc 'The prelinking feature changes binaries in an attempt to decrease their startup time.'
  describe package('prelink') do
    it { should_not be_installed }
  end
end

title '5 - OS Services'

control '5.1.1' do
  impact 0.1
  title '5.1.1 Ensure NIS is not installed (Scored)'
  desc 'The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files.'
  describe package('nis') do
    it { should_not be_installed }
  end
end

describe file('/etc/annie.txt') do
  it { should exist }
  its('content') { should match /annie was here/ }
end
