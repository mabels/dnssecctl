# dnssecctl
DNSSec Tool easy managing dnssec zones

very early


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
