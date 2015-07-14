#!/opt/puppet/bin/ruby
require 'puppet'
require 'hiera'
require 'facter'
require 'puppetclassify'

# Have puppet parse its config so we can call its settings
Puppet.initialize_settings

# Read classifier.yaml for split installation compatibility
def load_classifier_config
  configfile = File.join Puppet.settings[:confdir], 'classifier.yaml'
  if File.exist?(configfile)
    classifier_yaml = YAML.load_file(configfile)
    @classifier_url = "https://#{classifier_yaml['server']}:#{classifier_yaml['port']}/classifier-api"
  else
    Puppet.debug "Config file #{configfile} not found"
    puts "no config file! - wanted #{configfile}"
    exit 2
  end
end

def load_classifier()
  auth_info = {
    'ca_certificate_path' => Puppet[:localcacert],
    'certificate_path'    => Puppet[:hostcert],
    'private_key_path'    => Puppet[:hostprivkey],
  }
  unless @classifier
    load_classifier_config
    @classifier = PuppetClassify.new(@classifier_url, auth_info)
  end
end

def create_group(group_name,group_uuid,classes = {},node,parent)
  cputs "Creating #{group_name} Node Group"
  load_classifier
  groups = @classifier.groups
  current_group = groups.get_groups.select { |group| group['name'] == group_name}
  if current_group.empty?
    cputs "Creating #{group_name} group in classifier"
    groups.create_group({
      'name'    => group_name,
      'id'      => group_uuid,
      'classes' => classes,
      'parent'  => groups.get_group_id(parent),
      'rule'    => ["or", ["=", "name", node]]
    })
  end
end

def node_add(node_group, node, override = true)
  cputs "Adding #{node} to the #{node_group} Node Group"
  load_classifier
  groups = @classifier.groups


  # The current NC API does not allow you edit rule sets
  # Basically you have merge whats there, however this data is
  # an array so we shift the rule i.e. 'or' and append the pinned nodes.
  current_group = groups.get_groups.select { |group| group['name'] == node_group}

  raise "#{node_group} group missing!" if current_group.empty?

  if override
    rule = ["or",["=","name",node]]
  else
    rule = ["or",["=","name",node]] + current_group[0]['rule'].drop(1)
  end

   group_hash = {
    'name'    => node_group,
    'id'      => groups.get_group_id(node_group),
    'classes' => {},
    'parent'  => groups.get_group_id('PE Infrastructure'),
    'rule'    => rule
  }

  groups.update_group(group_hash)
end

def update_master(remote)
  cputs "Updating PE Master Node Group"
  load_classifier
  groups = @classifier.groups

  master_group = groups.get_groups.select { |group| group['name'] == "PE Master"}

  raise 'PE Master group missing!' if master_group.empty?

  source = {
    'mytest' => {
      'remote' => remote,
      'basedir' => '/etc/puppetlabs/puppet/environments'
    }
  }

  group_hash = master_group.first.merge({"classes" => {"r10k" => {'configfile' => '/etc/puppetlabs/r10k/r10k.yaml', 'sources' => source}}})
  groups.update_group(group_hash)
end

def kill_firewall()
  cputs "Terminating firewall"
  fw = Puppet::Resource.new('service','iptables', :parameters => {
    :ensure =>'stopped',
    :enable => false,
  })
  result, report = Puppet::Resource.indirection.save(fw)
  puts "Resource: #{report.status}"
  puts report.logs
end

def config_r10k(remote)
  cputs "Configuring r10k"
  load_classifier
  conf = Puppet::Resource.new("file",'/etc/puppetlabs/r10k/r10k.yaml', :parameters => {
    :ensure => 'file',
    :owner  => 'root',
    :group  => 'root',
    :mode   => '0644',
    :content => "cachedir: '/var/cache/r10k'\n\nsources:\n  test:\n    remote: '#{remote}'\n    basedir: '/etc/puppetlabs/puppet/environments'"
  })
  result, report = Puppet::Resource.indirection.save(conf)
  puts "Resource: #{report.status}"
  puts report.logs
  system('/opt/puppet/bin/r10k deploy environment -v -p')
  @classifier.update_classes.update
  update_master(remote)
end

def cputs(string)
  puts "\033[1m#{string}\033[0m"
end

kill_firewall
config_r10k('git://github.com/beergeek/puppet_env.git')
node_add("PE ActiveMQ Broker","com0.puppetlabs.vm")
node_add("PE Master","com0.puppetlabs.vm", false)
create_group("PE ActiveMQ Hub", '76926f43-be06-4ee9-ad69-08681d224c1a',{'puppet_enterprise::profile::amq::hub' => {}},'aio0.puppetlabs.vm','PE Infrastructure')
create_group("PE COM Master", '76926f43-be06-4ee9-ad69-08681d224c1b',{'pe_repo' => {'master' => 'puppet.puppetlabs.vm' }},'com0.puppetlabs.vm',"PE Master")
