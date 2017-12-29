#!/usr/bin/python3
import os
import sys
import json
import time
from easyzone import easyzone
import subprocess
import dns.resolver

def updateSoa(cbot_json):
  z = easyzone.zone_from_file(myDomain(cbot_json), myUnsignedRefFname(cbot_json, '.ref.soa'))
  print(z.root.soa.serial)
  z.save(autoserial=True)

def txtDomainLine(cbot_json):
  return "%s. 3600 IN TXT %s" % (cbot_json['txt_domain'], cbot_json['validation'])

def myDomain(cbot_json):
  return '.'.join(cbot_json['domain'].split('.')[1:])

def myDomainDir(cbot_json):
  return ''.join(['/etc/bind/zones.signed/', myDomain(cbot_json)])

def myUnsignedRefFname(cbot_json, ext = '.ref'):
  return '/'.join([myDomainDir(cbot_json), 'unsigned%s' % (ext)])

def myUnsignedRefFile(cbot_json):
  return [line.rstrip('\n') for line in open(myUnsignedRefFname(cbot_json))]

def updateTxtDomainLine(cbot_json, dnsList):
  domainFound = []
  txtFound = []
  out = []
  for idx, line in enumerate(dnsList):
    if line.startswith(cbot_json['txt_domain']):
      txtFound.append(idx)
    if line.startswith(cbot_json['domain']):
      domainFound.append(idx)
    out.append(line)
  print(domainFound)
  print(txtFound)
  if len(domainFound) <= 0 :
   return nil
  for i in txtFound:
   del out[i]

  out.insert(domainFound[-1] + 1, txtDomainLine(cbot_json))
  return out

def cleanTxtDomainLine(cbot_json, dnsList):
  return list(filter(lambda x: not (x.startswith(cbot_json['txt_domain']) and x.endswith(cbot_json['validation'])), dnsList))

def signZone(cbot_json):
  zoneSaltFname = '/'.join([myDomainDir(cbot_json), 'zone.salt'])
  if not os.path.isfile(zoneSaltFname) :
    return
  wd = os.getcwd()
  os.chdir(myDomainDir(cbot_json))
  salt = [line.rstrip('\n') for line in open(zoneSaltFname)][0]
  cmds = ["/usr/sbin/dnssec-signzone",
                  "-u", "-S", "-A", "-3", salt, "-N", "INCREMENT",
                  "-o", myDomain(cbot_json), "-t", myUnsignedRefFname(cbot_json)]
  print(' '.join(cmds))
  subprocess.run(cmds, stderr=subprocess.STDOUT)
  os.chdir(wd)

def rndc(cbot_json, cmd):
  subprocess.run(["/usr/sbin/rndc", cmd, myDomain(cbot_json)], stderr=subprocess.STDOUT)

def swapFname(fname1, fname2):
  swapFname = '-'.join([fname1, 'swapFname'])
  os.rename(fname1, swapFname)
  os.rename(fname2, fname1)
  os.rename(swapFname, fname2)

def waitForDns(cbot_json):
  res = dns.resolver.Resolver()
  nss = res.query(myDomain(cbot_json), 'ns')
  nssList = []
  for ns in nss:
    print(ns.to_text())
    nslist = []
    for a in res.query(ns.to_text(), 'a'):
     nslist.append(a.address)
    for a in res.query(ns.to_text(), 'aaaa'):
     nslist.append(a.address)
    nssList.append(nslist)
  found = False
  while not found :
    founds = []
    for ns in nssList:
      res = dns.resolver.Resolver(configure=False)
      print(ns)
      res.nameservers = ns
      txts = res.query(cbot_json['txt_domain'], 'txt')
      for txt in txts:
        for str in txt.strings:
          print("%s == %s %d" % (str.decode(), cbot_json['validation'], str.decode() == cbot_json['validation']))
          if str.decode() == cbot_json['validation'] :
            founds.append(txt)
    found = len(founds) == len(nssList)
    if not found :
      print('retry found:%d/%d' % (len(founds), len(nssList)))
      time.sleep(1)

cbot_json=json.loads(os.environ['cbot_json'])
print(cbot_json['cmd'])
if cbot_json['cmd'] == 'perform_challenge' :
  # print(myUnsignedRefFile(cbot_json))
  print(txtDomainLine(cbot_json))
  updated = updateTxtDomainLine(cbot_json, myUnsignedRefFile(cbot_json))
  if not updated :
    print('updateTxtDomainLine failed')
    sys.exit(9)
  #print(updated);
  outfile = open(myUnsignedRefFname(cbot_json, '.ref.orig'), 'w')
  outfile.write("\n".join(updated + ["\n"]))
  outfile.close()
  swapFname(myUnsignedRefFname(cbot_json), myUnsignedRefFname(cbot_json, '.ref.orig'))
  rndc(cbot_json, 'thaw')
  rndc(cbot_json, 'freeze')
  updateSoa(cbot_json)
  signZone(cbot_json)
  rndc(cbot_json, 'thaw')
  waitForDns(cbot_json)
  sys.exit(0)

if cbot_json['cmd'] == 'wait_for_dns' :
  waitForDns(cbot_json)
  sys.exit(0)

if cbot_json['cmd'] == 'clean_challenge' :
  print(myUnsignedRefFname(cbot_json, '.le'))
  outfile = open(myUnsignedRefFname(cbot_json, '.ref.orig'), 'w')
  outfile.write("\n".join(cleanTxtDomainLine(cbot_json, myUnsignedRefFile(cbot_json))))
  outfile.close()
  swapFname(myUnsignedRefFname(cbot_json), myUnsignedRefFname(cbot_json, '.ref.orig'))
  rndc(cbot_json, 'thaw')
  rndc(cbot_json, 'freeze')
  updateSoa(cbot_json)
  signZone(cbot_json)
  rndc(cbot_json, 'thaw')
  waitForDns(cbot_json)
  sys.exit(0)

if cbot_json['cmd'] == 'cleanup' :
  sys.exit(0)

sys.exit(7)
