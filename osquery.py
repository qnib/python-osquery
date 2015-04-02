#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""

Usage:
    osquery.py [options] [<QUERY>]

Options:
    --out <str>             Output mode (json,csv,line,list) [default: json]
    --templates             Output predefined SQL statements
    --sys <str>             OS Version (to be self discovered) [default: macosx]
    --sys-id <str>          Global identifier for system (Mainboard-SN?) [default: AFFE001]
    --neo4j                 Use neo4j server to fill inventory
    --host <str>            neo4j hostname [default: neo4j.service.consul]
    -h --help               Show this screen.
    --version               Show version.
    --loglevel, -L=<str>    Loglevel
                            (ERROR, CRITICAL, WARN, INFO, DEBUG)
    --log2stdout, -l        Log to stdout, otherwise to logfile.
    --logfile, -f=<path>    Logfile to log to (default: <scriptname>.log)
    --cfg, -c=<path>        Configuration file.

"""

# load librarys
import logging
import os
try:
    import envoy
except ImportError:
    HAVE_ENVOY=False
    import subprocess, shlex
else:
    HAVE_ENVOY=True
import sys
import socket
import re
import codecs
import ast
import time
from datetime import datetime
import json
from ConfigParser import RawConfigParser, NoOptionError

from neo4jrestclient.client import GraphDatabase, Node
from neo4jrestclient.query import QuerySequence
from requests.exceptions import ConnectionError

try:
    from docopt import docopt
except ImportError:
    HAVE_DOCOPT = False
else:
    HAVE_DOCOPT = True

__author__ = 'Christian Kniep <christian()qnib.org>'
__copyright__ = 'Copyright 2015 QNIB Solutions'
__license__ = """GPL v2 License (http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)"""


class QnibConfig(RawConfigParser):
    """ Class to abstract config and options
    """
    specials = {
        'TRUE': True,
        'FALSE': False,
        'NONE': None,
    }

    def __init__(self, opt):
        """ init """
        RawConfigParser.__init__(self)
        if opt is None:
            self._opt = {
                "--log2stdout": False,
                "--logfile": None,
                "--loglevel": "ERROR",
            }
        else:
            self._opt = opt
            self.log2stdout = False
            self.logformat = '%(asctime)-15s %(levelname)-5s [%(module)s] %(message)s'
            self.loglevel = self._opt['--loglevel']
            self.eval_cfg()

        self.eval_opt()
        self.set_logging()
        logging.info("SetUp of QnibConfig is done...")


    def do_get(self, section, key, default=None):
        """ Also lent from: https://github.com/jpmens/mqttwarn
            """
        try:
            val = self.get(section, key)
            if val.upper() in self.specials:
                return self.specials[val.upper()]
            return ast.literal_eval(val)
        except NoOptionError:
            return default
        except ValueError:  # e.g. %(xxx)s in string
            return val
        except:
            raise
            return val

    def __getitem__(self, item):
        """
        :param item: key to __dict__ or opt
        :return: value of key
        """
        if item in self.__dict__.keys():
            return self.__dict__[item]
        else:
            return self._opt[item]

    def config(self, section):
        ''' Convert a whole section's options (except the options specified
                explicitly below) into a dict, turning

                    [config:mqtt]
                    host = 'localhost'
                    username = None
                    list = [1, 'aaa', 'bbb', 4]

                into

                    {u'username': None, u'host': 'localhost', u'list': [1, 'aaa', 'bbb', 4]}

                Cannot use config.items() because I want each value to be
                retrieved with g() as above
            SOURCE: https://github.com/jpmens/mqttwarn
            '''

        d = None
        if self.has_section(section):
            d = dict((key, self.do_get(section, key))
                     for (key) in self.options(section) if key not in ['targets'])
        return d


    def eval_cfg(self):
        """ eval configuration which overrules the defaults
            """
        cfg_file = self._opt.get('--cfg')
        if cfg_file is not None:
            fd = codecs.open(cfg_file, 'r', encoding='utf-8')
            self.readfp(fd)
            fd.close()
            self.__dict__.update(self.config('defaults'))


    def eval_opt(self):
        """ Updates cfg according to options """

        def handle_logfile(val):
            """ transforms logfile argument
                """
            if val is None:
                logf = os.path.splitext(os.path.basename(__file__))[0]
                self.logfile = "%s.log" % logf.lower()
            else:
                self.logfile = val

        self._mapping = {
            '--logfile': lambda val: handle_logfile(val),
        }
        for key, val in self._opt.items():
            if key in self._mapping:
                if isinstance(self._mapping[key], str):
                    self.__dict__[self._mapping[key]] = val
                else:
                    self._mapping[key](val)
                break
            else:
                if val is None:
                    continue
                mat = re.match("\-\-(.*)", key)
                if mat:
                    self.__dict__[mat.group(1)] = val
                else:
                    logging.info("Could not find opt<>cfg mapping for '%s'" % key)


    def set_logging(self):
        """ sets the logging """
        if self.log2stdout:
            logging.basicConfig(level=self.loglevel,
                                format=self.logformat)
        else:
            logging.basicConfig(filename=self.logfile,
                                level=self.loglevel,
                                format=self.logformat)

    def __setitem__(self, key, value):
        """ set key/val
        """
        self.__dict__[key] = value

    def __str__(self):
        """ print human readble """
        ret = []
        for key, val in self.__dict__.items():
            if not re.match("_.*", key):
                ret.append("%-15s: %s" % (key, val))
        return "\n".join(ret)


class OsQuery(object):
    """ Class to hold the functioanlity of the script
    """

    def __init__(self, cfg):
        """ Init of instance
        """
        self._cfg = cfg
        self._cfg['cmd'] = "osqueryi --%(--out)s " % cfg
        self._system_hostname = socket.gethostname().split(".")[0]
        self._now = datetime.now().strftime("%F_%H-%M-%S")
        self._templates = {
            "ip4_ports": {
                "sql": {
                    "all": "SELECT p.pid, port, protocol, address,name,path,p.uid,username FROM listening_ports AS l JOIN processes AS p, users as u ON p.pid == l.pid WHERE family='2' AND u.uid == p.uid;",
                    },
                "desc": "Outputs open port listening on IPv4 sockets."
            },
            "ip6_ports": {
                "sql": {
                    "all": "SELECT p.pid, port, protocol, address,name,path,p.uid,username FROM listening_ports AS l JOIN processes AS p, users as u ON p.pid == l.pid WHERE family='30' AND u.uid == p.uid;",
                    },
                "desc": "Outputs open port listening on IPv6 sockets."
            },
            "software": {
                "desc": "Show installed software",
                "sql": {
                    "macosx": "SELECT name, path, bundle_short_version AS version, 'apps' as src FROM apps; SELECT name, path, version, 'homebrew_packages' as src FROM homebrew_packages;",
                    }
                },
            }
        if self._cfg['--neo4j']:
            url = "http://%(--host)s:7474" % self._cfg
            try:
                self._gdb = GraphDatabase(url)
            except ConnectionError:
                time.sleep(3)
                self.con_gdbp()
            self._labels = {
                "SYS": self._gdb.labels.create("SYSTEM"),
                "SW_BASE": self._gdb.labels.create("SW_BASE"),
                "SW_VER": self._gdb.labels.create("SW_VERSION"),
                "SW_INST": self._gdb.labels.create("SW_INSTALLATION"),
                }
            self.get_sys()

    def get_sys(self):
        """ Fetches systems GUID
        :return: system guid
        """
        query = "MATCH (me:SYSTEM {guid: '%(--sys-id)s'}) RETURN me" % self._cfg
        logging.info(query)
        res = self._gdb.query(query, returns=Node)
        self._system_node = self.unfold(res)
        if self._system_node is None:
            ## create node
            self._system_node = self._gdb.nodes.create(name=self._system_hostname, guid=self._cfg['--sys-id'])
            self._labels['SYS'].add(self._system_node)

    def upsert_software(self, sw):
        """ Update or Insert nodes to represent software
        :param sw: dict including name,path,version, src
        :return: None
        """
        query = "MATCH (node:SW_BASE {name: '%(name)s', path: '%(path)s', src:'%(src)s', version:'%(version)s'}) RETURN node" % sw
        logging.info(query)
        res = self._gdb.query(query, returns=Node)
        sw_base = self.unfold(res)
        if sw_base is None:
            sw_base = self._gdb.nodes.create(name=sw['name'], path=sw['path'], version=sw['version'], src=sw['src'])
            self._labels['SW_BASE'].add(sw_base)
        ## Need INSTALLATION node
        query = "MATCH (me:SYSTEM {guid: '%(--sys-id)s'})-[:HAS]->" % self._cfg
        query += "(sw_inst:SW_INSTALLATION)<-[:PART_OF]-"
        query += "(node:SW_BASE {name: '%(name)s', path: '%(path)s', src:'%(src)s', version:'%(version)s'}) RETURN sw_inst" % sw
        logging.info(query)
        res = self._gdb.query(query, returns=Node)
        sw_inst = self.unfold(res)
        if sw_inst is None:
            sw_inst = self._gdb.nodes.create(discovered=self._now, last_seen=self._now, vanished="0")
            self._labels['SW_INST'].add(sw_inst)
            sw_base.relationships.create("PART_OF", sw_inst)
            self._system_node.relationships.create("HAS", sw_inst)
        else:
            # TODO: touch sw_inst
            sw_inst['last_seen'] = self._now

        #self._system_node.relationships.create("IS_INSTALLED", sw_base)

    def unfold(self, res):
        """ evaluates result of CYPHER query
        :param res: result of neo4j-query
        :return: unfolded result or None
        """
        if isinstance(res, QuerySequence) and len(res) == 1:
            return res[0][0]
        if isinstance(res, list):
            ret = res.pop()
            self.unfold(ret)
        else:
            if isinstance(res, QuerySequence):
                return None
            return res

    def run(self):
        """ do something
        """
        if self._cfg['--templates']:
            for key, item in self._templates.items():
                print "%-15s > %s" % (key, item['desc'])
                if 'all' in item['sql'].keys():
                    sql = item['sql']['all']
                elif self._cfg['--sys'] in item['sql'].keys():
                    sql = item['sql'][self._cfg['--sys']]
                else:
                    sql = "Sorry, no SQL statement for your system '%(--sys)s'" % self._cfg
                print "%-15s > %s" % ("", sql)
        else:
            res = self.query()
            print "before-return"
            self.output(res)

    def output(self, res):
        """ outputs the result according to users whish
        :return:
        """
        if self._cfg['--neo4j']:
            for item in json.loads(res):
                self.upsert_software(item)
        elif self._cfg['--out'] == "json":
            print res

    def query(self):
        """
        :return: output of query result
        """
        query = self._cfg["<QUERY>"]
        if len(query.split()) == 1:
            if "all" in self._templates[query]['sql'].keys():
                self._cfg['sql'] = self._templates[query]['sql']['all']
            else:
                self._cfg['sql'] = self._templates[query]['sql'][self._cfg['--sys']]
        else:
            self._cfg['sql'] = query
        cmd = "%(cmd)s \"%(sql)s\"" % self._cfg
        return self.sql_exec(cmd)

    def sql_exec(self, cmd):
        """ Runs SQL statement and returns stdout
        :param cmd: SQL statement
        :return: stdout
        """
        if HAVE_ENVOY:
            proc = envoy.run(cmd)
            if proc.status_code != 0:
                logging.error("Something went wrong. STDOUT: %s | STDERR: %s" % (proc.std_out, proc.std_err))
                sys.exit(1)
            return proc.std_out
        else:
            p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
            p.wait()
            (stdout, _) = p.communicate()
            return stdout



def main():
    """ main function """
    options = None
    if HAVE_DOCOPT:
        options = docopt(__doc__, version='Test Script 0.1')
    qcfg = QnibConfig(options)
    mc = OsQuery(qcfg)
    mc.run()


if __name__ == "__main__":
    main()