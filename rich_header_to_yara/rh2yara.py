#!/usr/bin/env python3
import argparse
import hashlib
import logging
import sys
from pathlib import Path
import lief

__author__ = "malware4n6"
__copyright__ = "malware4n6"
__license__ = "The Unlicense"
__version__ = "0.0.1"

log = logging.getLogger(__name__)

def parse_args(args):
    parser = argparse.ArgumentParser(description="Rich Header to Yara")
    parser.add_argument("--version", action="version", version="rh2yara {ver}".format(ver=__version__))
    parser.add_argument("-i", "--input", help="path to some exe (use -i for each input file)",
                        type=str, required=True, action='append')
    parser.add_argument("-o", "--output",
                        help="path to generated Yara",
                        type=str, default=None)
    parser.add_argument("-v", "--verbose", dest="verbose", help="set loglevel to DEBUG",
                        action='store_true')
    return parser.parse_args(args)

def setup_logging(verbose=False):
    """
    if verbose, logging.loglevel is set to DEBUG instead of INFO
    warning: logging output is done on stderr
    """
    logformat = "[%(asctime)s] %(levelname)s\t%(name)s\t%(message)s"
    loglevel = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=loglevel, stream=sys.stderr, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )

class RichHeaderYaraGenerator():
    """
    usage:
    with RichHeaderYaraGenerator('my.yara') as yg:
        yg.start_yara()
        for exe in ('a.exe', 'b.exe'):
            yg.generate_rule_for_exe(exe)
    """
    def __init__(self, output):
        """
        output: a filename in which all Yara rules will be written
        """
        self.output = output
        self.log = logging.getLogger('rhyg')
    
    def __enter__(self):
        if self.output:
            self.fdout = open(self.output, 'w')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.output:
            self.fdout.close()

    def write_output(self, data):
        """
        as output can be written on stdout (print is used)
        or in a file, this function does the choice and
        sets the trailing charactter to '' instead of '\n'
        in case print() is used
        """
        if self.output:
            self.fdout.write(data)
        else:
            print(data, end='')

    def start_yara(self):
        """
        write the start of a Yara file
        """
        self.write_output(r'''import "pe"

''')

    def start_rule(self, binname, binhash):
        """
        write the start of a Yara rule (for a single file)
        binhash: string to display in the field meta.hash of the rule
        """
        name = binname.replace('.', '').replace('-', '')
        start = f'rule detect_{name}' + r''' {
    meta:
        hash = "''' + binhash + r'''"
    condition:
'''
        self.write_output(start)

    def end_rule(self, entries):
        """
        write the end of the rule, the *condition* part
        which will contain the pe.rich_signature... tests
        """
        end = r'''        // filesize < 10M and
        pe.is_pe and
'''
        self.write_output(end)
        text = ' and\n'.join([f'        pe.rich_signature.toolid({entry.id}, {entry.build_id}) == {entry.count}'
                                for entry in entries])
        self.write_output(text)
        self.write_output('\n}\n\n')

    def __get_hash_for_exe(self, exe):
        with open(exe, "rb") as fd:
            digest = hashlib.file_digest(fd, "sha256")
        return digest.hexdigest()

    def generate_rule_for_exe(self, exe):
        self.log.debug(f'-i {exe}')
        binary = lief.PE.parse(exe)
        if binary:
            if binary.has_rich_header:
                self.log.info(f'{exe} has Rich Header - working on it')
                exepath = Path(exe)
                hash = self.__get_hash_for_exe(exe)
                self.start_rule(exepath.name, hash)
                self.end_rule(binary.rich_header.entries)
            else:
                self.log.error(f'{exe} has no Rich Header')
        else:
            self.log.error(f'{exe} is not a PE')

def main(args):
    args = parse_args(args)
    setup_logging(args.verbose)

    with RichHeaderYaraGenerator(args.output) as yg:
        yg.start_yara()
        for exe in args.input:
            yg.generate_rule_for_exe(exe)

if __name__ == "__main__":
    main(sys.argv[1:])
