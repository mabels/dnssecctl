

require 'logger'
require 'fileutils'
require 'tmpdir'
require 'securerandom'
require 'getoptlong'


module DnsSec
  #BASE="/etc/bind/zones"
  #RESULT="/etc/bind/zones.signed"
  LOG = Logger.new(STDERR)
  module Templates
    TEMPLATES = {}
    def self.register_template(fname, mod)
      TEMPLATES[fname] = mod
    end

    def self.zone_bind_template(signer, fname)
      return <<-ZONE
zone "#{signer.domain_name(fname)}" {
  type master;
  file "#{File.join(signer.domain_dir(fname), "signed.zone")}";
  notify yes;
  allow-update {
    key "rndc-key";
  };
  allow-query { any; };
};
      ZONE
    end

    def self.template_for_filename(signer, fname)
      dname = signer.domain_name(fname)
      return TEMPLATES[dname] if TEMPLATES[dname]
      unless test_template(signer, dname, File.join(signer.domain_dir(fname), 'template.rb'))
        unless test_template(signer, dname, File.join(signer.base_dir, 'template.rb'))
          TEMPLATES[dname] = Templates
        end
      end

      return TEMPLATES[dname]
    end

    def self.test_template(signer, dname, tname)
      begin
        require tname
        return TEMPLATES[dname] if TEMPLATES[dname]
      rescue LoadError
      end

      return nil
    end
  end

  class Signer
    attr_reader :cmd
    def initialize(cmd)
      @cmd = cmd
      @templates = {}
    end

    def base_dir
      @cmd.base_dir
    end

    def domain_dir(fname)
      File.join(cmd.base_dir, domain_name(fname))
    end

    def mkdir(fname)
      FileUtils.mkdir_p domain_dir(fname)
      cmd.chown domain_dir(fname)
    end

    def domain_name(fname)
      File.basename(fname)
    end

    def ref_fname(fname)
      File.join(domain_dir(fname), "orignal.zone")
    end

    def system(a)
      LOG.debug(">>#{a}")
      Kernel.system(a) || throw("system command not successful #{a}")
    end

    def create_key(fname, name, options)
      return if File.file?(File.join(domain_dir(fname), "#{name}.key")) and
        File.file?(File.join(domain_dir(fname), "#{name}.private"))
      dir = Dir.mktmpdir
      cur_dir = Dir.pwd
      LOG.info "creating key #{name} for #{domain_name(fname)}"
      system "#{cmd.dnssec_keygen} -A -3 -K \"#{dir}\" #{options} -a RSASHA256 -n ZONE #{domain_name(fname)}"
      Dir.glob(File.join(dir, "K#{domain_name(fname)}*")).each do |i|
        dst_name = "#{name}#{File.extname(i)}"
        key_name = File.basename(i)
        LOG.debug("work on i=#{i} dst_name=#{dst_name} key_name=#{key_name}")
        FileUtils.copy i, File.join(domain_dir(fname), key_name)
        FileUtils.cd domain_dir(fname)
        # link to find the right file easy
        FileUtils.ln_s key_name, dst_name
        FileUtils.cd cur_dir
        cmd.chown key_name
        cmd.chown dst_name
        FileUtils.rm i
      end
      # remove the directory.
      FileUtils.remove_entry_secure dir
      Dir.chdir cur_dir
    end

    def prepare_zone(fname)
      zone = IO.read(fname)
      zone += "\n; signer.rb for domain #{domain_name(fname)}\n"
      zone += "$INCLUDE #{File.join(domain_dir(fname), File.basename(File.readlink(File.join(domain_dir(fname), "zsk.key"))))}\n"
      zone += "$INCLUDE #{File.join(domain_dir(fname), File.basename(File.readlink(File.join(domain_dir(fname), "ksk.key"))))}\n"
      unsigned = File.join(domain_dir(fname), "include_keys.zone")
      File.open(unsigned, 'w') { |file| file.write(zone) }
      cmd.chown unsigned
      return unsigned
    end

    def init_domain(fname)
      LOG.info "init domain #{domain_name(fname)} from #{fname}"
      FileUtils.rm_rf domain_dir(fname)
      mkdir(fname)
      FileUtils.copy fname, ref_fname(fname)
      create_key(fname, "zsk", "-b 2048")
      create_key(fname, "ksk", "-f KSK -b 4096")
      unsigned_fname = prepare_zone(fname)
      sign_zone(fname, unsigned_fname)
      create_zone_block(fname)
      return true
    end

    def sign_zone(zone, unsigned_fname = nil)
      signed_fname = File.join(domain_dir(zone), "signed.zone")
      unsigned_fname ||= signed_fname
      system "#{cmd.dnssec_signzone} -A -3 #{SecureRandom.hex[0,16]} -N INCREMENT -t "+
        "-f #{signed_fname} "+
        "-o #{domain_name(zone)} "+
        "-K #{domain_dir(zone)} "+
        "-d #{domain_dir(zone)} "+
        "#{unsigned_fname}"
      cmd.chown signed_fname
    end

    def self.remove_zone(cmd)
      signer = Signer.new(cmd)
      LOG.info("Remove zone #{signer.domain_dir(fname)}")
      FileUtils.rm_r(signer.domain_dir(fname))
    end

    def self.reload(cmd)
      LOG.info("Reload configuration file and zones.")
      Signer.new(cmd).system("#{cmd.rndc} reload")
    end

    def self.init_domains(cmd)
      reloads = false
      signer = Signer.new(cmd)
      cmd.argv.each do |fname|
        unless File.file?(fname)
          LOG.error("zone file not found #{fname}")
        else
          LOG.info("init zone from #{fname} to #{cmd.base_dir}")
          reloads |= signer.init_domain(fname)
        end
      end
      return reloads
    end

    def self.commander(cmd, &block)
      signer = Signer.new(cmd)
      cmd.argv.each do |zone|
        if File.file?(File.join(cmd.base_dir, zone, "signed.zone"))
          block.call(signer, zone)
        else
          LOG.error("zone not found #{zone}")
        end
      end
    end

    def create_zone_block(fname)
      template = Templates.template_for_filename(self, fname)
      named_block_fname = File.join(domain_dir(fname),  "named.block")
      File.open(named_block_fname, 'w') { |file| file.write(template.zone_bind_template(self, fname)) }
      cmd.chown named_block_fname
    end

    def self.rebuild_named_conf_local_signed(cmd)
      signer = Signer.new(cmd)
      fname = File.join(cmd.base_dir, "named.conf.local.signed")
      File.open(fname,  'w') do |file|
        Dir.glob(File.join(cmd.base_dir, "*", "named.block")).each do |named_block_fname|
          LOG.info("add named.block for #{File.basename(signer.domain_dir(named_block_fname))}")
          file.puts("$INCLUDE #{named_block_fname}");
        end
      end

      cmd.chown fname
    end
  end

  class Ctl
    OPTS = GetoptLong.new(
      [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
      [ '--base-dir', '-b', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--resign-time', '-r', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--dnssec-keygen', '-k', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--dnssec-signzone', '-s', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--rndc', '-c', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--user', '-u', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--group', '-g', GetoptLong::REQUIRED_ARGUMENT ]
    )
    attr_reader :cmd, :base_dir, :resign_time, :user, :group, :argv

    def find_os_tool(name)
      ([File.dirname(name)]+ENV['PATH'].split(":")+["/sbin","/usr/sbin","/usr/local/sbin"]).sort.uniq.each do |path|
        fname = File.join(path, name)
        return fname if File.executable?(fname)
      end
      log.warn("the os tool #{name} not found")
    end

    def dnssec_signzone
      find_os_tool(@dnssec_signzone)
    end
    def dnssec_keygen
      find_os_tool(@dnssec_keygen)
    end
    def rndc
      find_os_tool(@rndc)
    end

    def initialize
      @base_dir = "/etc/bind/zones.signed"
      @resign_time = 60*24*3 # 3 days
      @dnssec_keygen = "dnssec-keygen"
      @dnssec_signzone = "dnssec-signzone"
      @user = "bind"
      @group = "bind"
      @rndc = "rndc"
    end

    def help
      return unless @help
      puts <<-EOF
hello [OPTION] ... DIR

-h, --help:
   show help

init:
  initialize zones from unsigned domain files.

cron:
  runs a resigning if the file is older than the given
  resigning time. default 3 days

edit:
  spawns a editor for the given zones and sign the changed files
        if required
freeze:
  freeze the zone for editing

thaws:
  thaws the zone and signs if required

--basedir,-b:
  base directory where the signed zone files are stored

--dnssec-keygen,-k
  path to dnssec-keygen tool

--dnssec-signzone,-k
  path to dnssec-signzone tool

--rndc,-c
  path to rndc tool

--user,-u
  user of the bind files

--group,-g
  group of the bind files


--resign-time,-r:
  the time in minutes to resigned the zone file in basedirectory path
      EOF
      system.exit(0)
    end

    def chown(fname)
      begin
        FileUtils.chown(user, group, fname)
      rescue Exception => e
        LOG.warn("can't change owner of #{fname} to #{user}:#{group}")
      end
    end

    def self.parse
      return Ctl.new.parse
    end

    def parse
      OPTS.each do |opt, arg|
        case opt
        when '--help'
          @help = true
        when "--dnssec-keygen"
          @dnssec_keygen = arg
        when "--dnssec-signzone"
          @dnssec_signzone = arg
        when "--rndc"
          @rndc = arg
        when "--resign-time"
          @resign_time = arg.to_i
        when "--base-dir"
          @base_dir = arg
        end
      end

      opt = ARGV.select{|i| not i.start_with?("-") }
      @cmd = opt.first
      @argv = opt[1..-1]
      return self
    end
  end

  module Command
    module Init
      def self.run(cmd)
        if DnsSec::Signer.init_domains(cmd)
          DnsSec::Signer.rebuild_named_conf_local_signed(cmd)
          DnsSec::Signer.reload(cmd)
        end
      end
    end

    module Cron
      def self.run(cmd)
        puts self.name
      end
    end

    module Edit
      def self.run(cmd)
        puts self.name
      end
    end

    module Remove
      def self.run(cmd)
        DnsSec::Signer.remove_zone(cmd)
      end
    end

    module Freeze
      def self.run(cmd)
        DnsSec::Signer.commander(cmd) do |signer, zone|
          signed_zone_freezed = File.join(signer.domain_dir(zone), "signed.zone.freezed")
          unless File.exist?(signed_zone_freezed)
            signer.system("#{cmd.rndc} freeze #{zone}")
            FileUtils.copy File.join(signer.domain_dir(zone), "signed.zone"), signed_zone_freezed
          else
            LOG.warn("this zone has been freeze before #{zone}, skipping!")
          end
        end
      end
    end

    module Thaw
      def self.run(cmd)
        DnsSec::Signer.commander(cmd) do |signer, zone|
          signed_zone_freezed = File.join(signer.domain_dir(zone), "signed.zone.freezed")
          if File.exist?(signed_zone_freezed)
            signed_zone = File.join(signer.domain_dir(zone), "signed.zone")
            unless FileUtils.compare_file(signed_zone_freezed, signed_zone)
              signer.sign_zone(zone)
              signer.system("#{cmd.rndc} thaw #{zone}")
              FileUtils.rm signed_zone_freezed
            else
              LOG.warn "zone #{zone} was not changed, skipping!"
            end
          else
            LOG.warn("the zone #{zone} has not been freeze before, skipping!")
          end
        end
      end
    end

    def self.run(cmd)
      ({ "init" => Init,
         "cron" => Cron,
         "edit" => Edit,
         "remove" => Remove,
         "freeze" => Freeze,
         "thaw" => Thaw}[cmd.cmd] ||
      throw("command not found #{cmd.cmd}")).run(cmd)
    end
  end
end

cmd = DnsSec::Ctl.parse
cmd.help
DnsSec::Command.run(cmd)

#DnsSec::Signer.domains(Dir.glob("/etc/bind/zones/*"))
#	end

#end
