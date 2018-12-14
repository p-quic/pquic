"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""
import argparse
import datetime
import os
import sqlite3
import time

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.link import TCLink, TCULink, TCIntf
from mininet.node import Node, CPULimitedHost
from mininet.topo import Topo
from mininet.clean import cleanup as net_cleanup

from topo_3h_5s_2r_kite import teardown_net
from topo_3h_5s_2r_kite import KiteTopo, setup_net

#mininet patch
from mininet.log import error
from mininet.link import TCIntf
@staticmethod
def delayCmds(parent, delay=None, jitter=None,
               loss=None, max_queue_size=None ):
    "Internal method: return tc commands for delay and loss"
    cmds = []
    if delay and delay < 0:
        error( 'Negative delay', delay, '\n' )
    elif jitter and jitter < 0:
        error( 'Negative jitter', jitter, '\n' )
    elif loss and ( loss < 0 or loss > 100 ):
        error( 'Bad loss percentage', loss, '%%\n' )
    else:
        # Delay/jitter/loss/max queue size
        netemargs = '%s%s%s%s' % (
            'delay %s ' % delay if delay is not None else '',
            '%s ' % jitter if jitter is not None else '',
            'loss %0.4f ' % loss if loss is not None else '',  # The fix
            'limit %d' % max_queue_size if max_queue_size is not None
            else '' )
        if netemargs:
            cmds = [ '%s qdisc add dev %s ' + parent +
                     ' handle 10: netem ' +
                     netemargs ]
            parent = ' parent 10:1 '
    return cmds, parent
TCIntf.delayCmds = delayCmds
# end mininet patch


class TypeWrapper(object):
    def __init__(self, type_builtin, name):
        self.builtin = type_builtin
        self.name = name

    def __call__(self, *args, **kwargs):
        return self.builtin(*args, **kwargs)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


int = TypeWrapper(int, "INTEGER")
float = TypeWrapper(float, "REAL")
str = TypeWrapper(str, "TEXT")


def load_wsp(filename, nrows, ncols):
    # Open the file
    f = open("%s" % filename)
    lines = f.readlines()
    f.close()

    # The interesting line is the third one
    line = lines[2]
    split_line = line.split(",")
    nums = []

    for x in split_line:
        nums.append(float(x))
    print(len(split_line))
    print(len(nums))

    if len(nums) != nrows*ncols:
        raise Exception("wrong number of elements in wsp matrix: %d instead of %d(with %d rows)" % (len(nums), nrows*ncols, nrows))

    print("load matrix")

    # The matrix is encoded as an array of nrowsxncols
    matrix = []
    for i in range(nrows):
        row = []
        for j in range(ncols):
            try:
                row.append(nums[i * ncols + j])
            except:
                print(i * ncols + j)
                raise

        matrix.append(row)

    return matrix


class ParamsGenerator(object):
    def __init__(self, params_values, matrix):
        self.index = 0
        self.params_values = params_values
        for k in ('delay_ms_a', 'delay_ms_b'):
            if isinstance(params_values.get(k, None), list):
                for i in range(len(params_values[k])):
                    params_values["%s_%d" % (k, i)] = params_values[k][i]
                params_values.pop(k, None)
        self.param_names = list(sorted(params_values.keys()))
        self.ranges_full_name = {self._full_name(key, val["count"]): val["range"] for key, val in params_values.items()}
        names = []
        for n in params_values.keys():
            for key in params_values[n]["range"].keys() if isinstance(params_values[n]["range"], dict) else [None]:
                names.append((n, key))
        self.param_full_names = sorted(flatten(map(lambda name_key: [self._full_name(name_key[0], i, name_key[1]) for i in range(params_values[name_key[0]]["count"])], names)))
        # decide for an arbitrary ordering of the parameters
        print self.param_full_names
        self.params_indexes = {self.param_full_names[i]: i for i in range(len(self.param_full_names))}
        self.matrix = matrix

    def _full_name(self, name, count, key=None):
        if self.params_values[name]["count"] > 1:
            return "%s_%d%s" % (name, count, ("_%s" % str(key)) if key is not None else "")
        return "%s%s" % (name, ("_%s" % str(key)) if key is not None else "")

    def generate_value(self):
        retval = self._generate_value_at(self.index)
        self.index += 1
        return retval

    def _generate_value_at(self, i):
        retval = {}
        for name in self.param_names:
            retval[name] = []
            for count in range(self.params_values[name]["count"]):
                param_range = self.params_values[name]["range"]
                if isinstance(param_range, dict):
                    to_append = {key: self.params_values[name]["type"](
                              self.matrix[self.params_indexes[self._full_name(name, count, key)]][i] * (param_range[key][1] - param_range[key][0]) + param_range[key][0])
                        for key in param_range.keys()}
                else:
                    full_name = self._full_name(name, count)
                    param_index = self.params_indexes[full_name]
                    float_value = self.matrix[param_index][i]
                    to_append = self.params_values[name]["type"](float_value * (param_range[1] - param_range[0]) + param_range[0])
                retval[name].append(to_append)
        return retval

    def __len__(self):
        return len(self.matrix[0])

    def generate_all_values(self):
        for i in range(len(self.matrix[0])):
            yield self._generate_value_at(i)

    def generate_sql_create_table(self, additional_values):
        lines = []
        for name in self.param_names:
            for count in range(self.params_values[name]["count"]):
                if isinstance(self.params_values[name]["range"], dict):
                    for k in sorted(self.params_values[name]["range"].keys()):
                        lines.append("%s %s NOT NULL" % (self._full_name(name, count, k),
                                                         str(self.params_values[name]["type"])))
                else:
                    lines.append("%s %s NOT NULL" % (self._full_name(name, count), str(self.params_values[name]["type"])))

        for name, type in additional_values:
            lines.append("%s %s NOT NULL" % (name, str(type)))

        return """
        CREATE TABLE IF NOT EXISTS results (
          %s
        );
        """ % (',\n'.join(lines))

    @staticmethod
    def generate_sql_insert(vals):
        retval = []
        for v in vals:
            if isinstance(v, dict):
                retval += [str(v[k]) for k in sorted(v.keys())]
            else:
                retval.append("'%s'" % str(v))
        print """ INSERT INTO results VALUES (%s); """ % ", ".join(retval)
        return """ INSERT INTO results VALUES (%s); """ % ", ".join(retval)


def flatten(l):
    """
        inefficiently flattens a list
        l: an arbitrary list
    """
    if not l:
        return l
    if isinstance(l[0], list):
        return flatten(l[0]) + flatten(l[1:])
    return [l[0]] + flatten(l[1:])


def generate_random_files(file_sizes):
    """
        Generates random files according to the given sizes.
        The files will be placed in the current directory with a filename of the form `random_%d` % size
    """
    for s in file_sizes:
        with open('random_%d' % s, 'wb') as f:
            f.write(os.urandom(s))


if __name__ == "__main__":
    from os import sys, path
    dir_path = path.dirname(path.abspath(__file__))
    sys.path.append(dir_path)

    ranges = {
        #"bw_a": {"range": [0.5, 15], "type": int, "count": 1},  # Mbps
        #"loss_a": {"range": [0.1, 2], "type": float, "count": 1},  # %, TODO: Characterise typical losses with LTE
        #"delay_ms_a": {"range": [100, 400], "type": int, "count": 1},  # ms
        "bw_b": {"range": [10, 30], "type": int, "count": 1},  # Mbps
        #"loss_b": {"range": [0.01, 1], "type": float, "count": 1},  # %
        "delay_ms_b": {"range": [5, 25], "type": int, "count": 1},  # ms
    }

    file_sizes = (1500, 10000, 50000, 1000000, 10000000)
    generate_random_files(file_sizes)
    nets_opts = [{'quic_tun': False, 'ip_tun': False}, {'quic_tun': True, 'ip_tun': True, 'tcpdump': True}]
    tests = ('tcp_over_path_b', 'tcp_over_picoquicvpn')

    filename = os.path.join(dir_path, "wsp_owd_8")
    nrows, ncols = 8, 139
    matrix = load_wsp(filename, nrows, ncols)
    gen = ParamsGenerator(ranges, matrix)
    vals = gen.generate_all_values()
    # vals = generate_variance_tests(ranges)

    conn = sqlite3.connect(os.path.join(dir_path, 'results.db'))
    cursor = conn.cursor()
    sql_create_table = gen.generate_sql_create_table(additional_values=[('test_name', str), ('elapsed_time', float), ('var_elapsed_time', float), ('file_size', int)])
    print sql_create_table
    cursor.execute(sql_create_table)
    conn.commit()

    setLogLevel('info')

    for i, v in enumerate(list(vals)[0:]):
        for key, value in v.items():
            if isinstance(value, list):
                v[key] = value[0]

        for setup_nets_opts, test_name in zip(nets_opts, tests):
            print "net config == " + str(setup_nets_opts)
            print "v == " + str(v)

            topo = KiteTopo(**v)
            net = Mininet(topo, link=TCLink, host=CPULimitedHost)
            net.start()
            setup_net(net, **setup_nets_opts)

            print "experiment %d/%d" % (i, len(gen))
            for size in file_sizes:
                print "file size %d" % size

                client = net['cl']
                server = net['web']

                def run():
                    now = datetime.datetime.now()
                    client.cmd('curl 10.3.0.2/random_%d --connect-timeout 5 --output /dev/null' % size)
                    err = int(client.cmd("echo $?"))
                    if err != 0:
                        print("client returned err %d" % err)
                        return 0
                    elapsed_ms = (datetime.datetime.now() - now).total_seconds() * 1000
                    time.sleep(1)
                    print "elapsed: %f milliseconds for %s" % (elapsed_ms, test_name)
                    return elapsed_ms

                results = list(filter(lambda x: x, sorted(run() for _ in range(9))))
                avg = sum(results) / len(results)
                median = results[int(len(results)/2)]
                std_dev = sum(abs(x - avg) for x in results) / len(results)
                print "median = %dms, avg = %dms, std_dev = %dms" % (median, avg, std_dev)

                # ugly way to handle failed results...
                values_list = flatten([v[k] for k in sorted(v.keys())]) + [test_name, median, std_dev, size]
                sql_values_list = gen.generate_sql_insert(values_list)
                print sql_values_list
                cursor.execute(sql_values_list)
                conn.commit()
                print "committed"

            teardown_net(net)
            net.stop()
            net_cleanup()
