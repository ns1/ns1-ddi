#!/usr/bin/env python3
""" Collect diagnostics from Kubernetes runtime and containers """

# Curently requires Python 3.7 and up. On Ubunutu 18.04 do:
#    apt-get install python3.7

from datetime import datetime
import logging
import os
import subprocess
import sys

import json


def _check_exec(func):
    """ Decorator to catch execution errors from shell commands """
    def wrapper(*args, **kwargs):
        firstarg = 0 if isinstance(args[0], str) else 1
        try:
            ret = func(*args, **kwargs)
        except (OSError, IOError, subprocess.CalledProcessError,
                ValueError) as exc:
            logging.error('command args "%s" encountered error: %s',
                          args[firstarg:], exc)
            return None
        if isinstance(ret, dict) and 'status' in ret:
            if len(ret['stderr']) > 0:
                logging.warning('command "%s" had stderr "%s"',
                                args[firstarg:], ret['stderr'])
            if ret['status'] != 0:
                logging.warning('command "%s" had non-zero exit status:%s',
                                args[firstarg:], ret['status'])
        return ret

    return wrapper


def shell(command, input_string="", check=False, cwd=None):
    """ Run a shell command and format everything nicely. The calling func
      should use the @check_exec decorator. """
    pipe = subprocess.run(args=command,
                          input=bytearray(input_string, 'utf-8'),
                          capture_output=True,
                          shell=True,
                          check=check,
                          cwd=cwd)
    stdout = pipe.stdout
    stdout = stdout.decode('utf-8')
    stderr = pipe.stderr
    stderr = stderr.decode('utf-8')
    return {
        'status': pipe.returncode,
        'args': pipe.args,
        'input': input_string,
        'stdout': stdout,
        'stderr': stderr
    }


class Executor:
    """ Execute commands via kubectl or locally. """

    @staticmethod
    @_check_exec
    def get_json(cmd, namespace):
        """ Extract Kubernetes status or config in JSON format. """
        args = f'kubectl {cmd} -o json' + \
                (f' -n {namespace}' if namespace is not None else '')
        pipe = shell(args, check=True)
        if pipe is None:
            return None
        try:
            result = json.loads(pipe['stdout'])
        except json.JSONDecodeError as j:
            logging.error('command "%s": JSON decoding error: %s', args, j)
            return None
        return {
            'status': pipe['status'],
            'args': pipe['args'],
            'stdout': result,
            'stderr': pipe['stderr']
        }

    @staticmethod
    @_check_exec
    def get_logs(pod_name):
        """ Extract Kubernetes container logs. """
        args = f'kubectl logs --all-containers --timestamps {pod_name}'
        return shell(args, check=True)

    @staticmethod
    @_check_exec
    def exec(pod, cmd):
        """ Run a command on the local host or in a Kubernetes container. """
        if pod == 'localhost':
            args = 'bash'
        else:
            args = f'kubectl exec -i {pod} -- bash'
        return shell(args, input_string=cmd)

    @staticmethod
    @_check_exec
    def copy(source, dest, localhost=False, namespace=None):
        """ Copy files from containers or local host into workdir. """
        if not localhost:
            if ':' in source and ':' in dest:
                raise ValueError(
                    "cannot have colon character in both source and dest")
            if ':' in source:
                source = f'{namespace}/{source}'
            if ':' in dest:
                dest = f'{namespace}/{dest}'
            args = f'kubectl cp {source} {dest}'
        else:
            source = source.replace('localhost:', '')
            dest = dest.replace('localhost:', '')
            args = f'cp -pr {source} {dest}'

        return shell(args, check=True)


class K8sDiags:
    """ Kubernetes-aware diagnostic methods. """

    def __init__(self, tmpdir=None):
        self.tmpdir = os.path.join(
            tmpdir if tmpdir else os.getenv('TMPDIR', '/tmp'), 'k8sdiags')
        self.k = Executor()
        now = datetime.now()
        self.workdir = os.path.join(self.tmpdir,
                                    now.strftime("diags-%Y-%m-%d_%H%M%S"))
        self.create_workdir()

        logger = logging.getLogger('')
        logger.setLevel(logging.DEBUG)
        handlers = [
            (logging.FileHandler(os.path.join(self.workdir,
                                              'k8sdiag.log')), logging.DEBUG),
            (logging.StreamHandler(sys.stderr), logging.WARNING)
        ]
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s')
        for htup in handlers:
            htup[0].setFormatter(formatter)
            htup[0].setLevel(htup[1])
            logger.addHandler(htup[0])

        result = self.k.get_json('get namespaces', None)
        if result is None or result['status'] != 0:
            raise EnvironmentError('Error invoking kubectl, logged above')
        self.namespaces_json = result['stdout']
        self.namespaces = []
        for item in self.namespaces_json['items']:
            self.namespaces.append(item['metadata']['name'])

        # namespace-independent data collection - namespace ignored
        result = self.k.get_json(f'get nodes', 'default')
        self.nodes = result['stdout']

        # namespace-specific data collection
        self.kubedata = {}
        for namespace in self.namespaces:
            namespace_dir = os.path.join(self.workdir, namespace)
            os.makedirs(namespace_dir, exist_ok=True)
            self.kubedata[namespace] = {}
            for thing in ['pods', 'events', 'services', 'deployments', 'configmap']:
                result = self.k.get_json(f'get {thing}', namespace)
                self.kubedata[namespace][thing] = result['stdout'] if result is not None else None

    def archive(self, path=None):
        """ Create a tarball of the results. """
        @_check_exec
        def myshell(*args, **kwargs):
            """ Sub-function to let decorator access command arguments. """
            return shell(*args, **kwargs)

        cwd = self.tmpdir
        relative_workdir = os.path.basename(self.workdir)
        if path is None:
            path = os.path.join(self.tmpdir,
                                os.path.basename(self.workdir) + '.tgz')
        pipe = myshell(f'tar cvzf {path} {relative_workdir}',
                       check=True,
                       cwd=cwd)
        if pipe is not None:
            pipe['tar_file'] = path
        return pipe

    def create_workdir(self):
        """ Create the workdir which will hold the results of this run. """
        try:
            os.makedirs(self.workdir, exist_ok=True)
        except (IOError, OSError, FileNotFoundError) as exc:
            logging.error('cannot create temporary directory "%s": %s',
                          self.workdir, exc)
            sys.exit(1)

    def save_json(self):
        """ Save collected data at specified path. """
        try:
            with open(os.path.join(self.workdir, 'nodes.json'),
                      'w') as fref:
                json.dump(self.nodes, fref, indent=2)
            for namespace in self.namespaces:
                for item in self.kubedata[namespace]:
                    with open(os.path.join(self.workdir, namespace, f'{item}.json'),
                              'w') as fref:
                        json.dump(self.kubedata[namespace][item], fref, indent=2)
        except (IOError, OSError) as exc:
            logging.error('cannot save K8s data: %s', exc)

    def match_labels(self, labels):
        """ Find pods that match all labels in argument. """
        results = []
        for namespace in self.kubedata:
            try:
                for pod in self.kubedata[namespace]['pods']['items']:
                    found = 0
                    for lab in labels:
                        for labelname in lab:
                            if lab[labelname] == pod['metadata']['labels'][labelname]:
                                found += 1
                    if found == len(labels):
                        results.append((namespace, pod['metadata']['name']))
            except KeyError:
                continue
        return results

    def k8s_node_checks(self):
        """ Report any node issues observed in Kubernetes status """

        for node in self.nodes['items']:
            node_name = node['metadata']['name']
            for status_check in node['status']['conditions']:
                for alert in NODE_CONDITION_ALERTS:
                    if alert == status_check['type'] and \
                        NODE_CONDITION_ALERTS[alert] == status_check['status']:
                        message = status_check['message'] if 'message' in status_check else "(no further information)"
                        logging.error('[%s] Kubernetes condition in alert state: %s', node_name, message)

    def k8s_event_checks(self):
        """ Report any pod issues observed in Kubernetes events. """

        results = {}
        for namespace in self.namespaces:
            if 'events' not in self.kubedata[namespace]:
                continue
            if len(self.kubedata[namespace]['events']['items']) == 0:
                logging.info('[namespace %s] no events found', namespace)
                continue
            for item in self.kubedata[namespace]['events']['items']:
                if item['type'] != 'Normal':
                    namespace = item['involvedObject'].get('namespace')
                    namespace_prefix = '' if namespace is None else namespace + '/'

                    pod_name = namespace_prefix + item['involvedObject']['name']
                    if not pod_name in results:
                        results[pod_name] = {'count': 0, 'types': set(), 'messages': set()}
                    results[pod_name]['count'] += 1
                    results[pod_name]['types'] |= {item['type']}
                    results[pod_name]['messages'] |= {item['message']}
            if len(results) > 0:
                for item in results:
                    logging.warning('[namespace %s] %d abnormal events for object %s: types %s, messages %s',
                                    namespace, results[item]['count'], item,
                                    results[item]['types'], results[item]['messages'])

    def run_by_label(self, spec):
        """ Run commands in pods that match all specified labels. """
        cmds = spec['cmds']
        copy = spec['copy'] if 'copy' in spec else []
        localhost = 'localhost' in spec and spec['localhost'] is True

        target_pods = []
        try:
            if localhost:
                target_pods = [('localhost', 'localhost')]
            else:
                status = 'searching pods for matching labels'
                target_pods = self.match_labels(spec['labels'])

            if len(target_pods) == 0:
                logging.info('no pods match requested labels: %s', spec['labels'])
                return None

            results = {}
            status = 'creating result struct'
            for namespace, pod_name in target_pods:
                results[pod_name] = []

                pod_dir = os.path.join(self.workdir, namespace, pod_name)
                status = 'creating workdir {pod_dir}'
                os.makedirs(pod_dir, exist_ok=True)

                status = "getting logs from pod"
                if not localhost:
                    ret = self.k.get_logs(pod_name)
                    if ret is not None:
                        with open(
                                os.path.join(pod_dir,
                                             f'podlogs-{pod_name}.txt'),
                                'w') as fref:
                            fref.write(ret['stdout'])

                i = 0
                while i < len(cmds):
                    status = 'running diag commands from table'
                    print(f' ... running: {cmds[i]}')
                    ret = self.k.exec(pod_name, cmds[i])
                    results[pod_name].append(ret)
                    status = 'writing command output to archive'
                    with open(os.path.join(pod_dir, f'cmd_{i:03}.json'),
                              'w') as fref:
                        json.dump(ret, fref, indent=2)
                    i += 1

                status = f'copying files out of pod "{pod_name}"'
                i = 0
                while i < len(copy):
                    if copy[i] == "LAST":
                        target_file = results[pod_name][-1]['stdout'].strip()
                    else:
                        target_file = copy[i]
                    print(f"... retrieving {pod_name}:{target_file}")
                    ret = self.k.copy(
                        f'{pod_name}:{target_file}',
                        os.path.join(self.workdir, namespace, pod_name,
                                     os.path.basename(target_file)),
                        localhost,
                        namespace)
                    results[pod_name].append(ret)
                    i += 1

            return results

        except (AttributeError, KeyError, TypeError, IOError, OSError) as exc:
            logging.error('EXCEPTION while %s: %s', status, exc)

# Issue an alert for any node condition whose type and status match
# the key/value pairs below.
NODE_CONDITION_ALERTS = {
    "Ready": "False",
    "PIDPressure": "True",
    "DiskPressure": "True",
    "MemoryPressure": "True",
    "NetworkUnavailable": "True",
    "ContainersReady": "False"
    }

POD_DIAGS = [{
    'name':
    'dns-pod',
    'labels': [{
        'app': 'ns1-cmddi-dns'
    }],
    'cmds': [
        'supd health',
        'supd viewconfig -yn', 'supd generate_runtime_logs', 'lsof -i :53',
        'curl -sS -I -x http://ns1-proxy:5353/ https://github.com',
        'dview -path /ns1/data/var/lib/trex-cache/dns/',
        'unbound-control status',
        'unbound-control stats_noreset',
        'unbound-control dump_cache',
        'unbound-control dump_requestlist',
        'unbound-control dump_infra',
        'unbound-control list_stubs',
        'unbound-control forward',
        'unbound-control list_forwards',
        'unbound-control list_insecure',
        'unbound-control list_local_zones',
        'unbound-control list_local_data',
        'unbound-control ratelimit_list',
        'unbound-control ip_ratelimit_list',
        'bash -c "sleep 3; dig www.ns1.com A" & tcpdump -i any -w /tmp/cmddi-dns-diag.tcp -A port 53 or port 530 or port 531 2>&1 & sleep 10; kill $!',
        'ls -t /ns1/data/log/health | sed -e s,^,/ns1/data/log/health/, | head -1'
    ],
    'copy': [
        'LAST', '/ns1/data/log_bak', '/tmp/cmddi-dns-diag.tcp',
        '/etc/resolv.conf'
    ]
}, {
    'name':
    'dhcp-pod',
    'labels': [{
        'app': 'ns1-cmddi-dhcp'
    }],
    'cmds': [
        'supd health',
        'curl -sS -I -x http://ns1-proxy:5353/ https://github.com',
        'supd viewconfig -yn', 'supd generate_runtime_logs'
    ],
    'copy': ['/ns1/data/log_bak', '/ns1/data/leases']
}, {
    'name': 'ns1-proxy-pod',
    'labels': [{
        'app': 'ns1-proxy'
    }],
    'cmds': ['grep address:.[^0] /etc/envoy/envoy.yaml'],
}, {
    'name': 'local',
    'localhost': True,
    'labels': [],
    'cmds': [
        'cat /etc/ns1/node_id',
        'uname -a; echo; cat /etc/lsb-release',
        'ls -l /etc/resolv.conf; echo; cat /etc/resolv.conf',
        'free; echo; df',
        'ip route; echo; ip neighbor',
        'ss -apn || netstat -apn',
        'iptables -Ln',
        'dig +short rs.dns-oarc.net TXT',
        'dig +short rs.dns-oarc.net TXT @localhost',
        'pstree -a',
        'ps -ef',
        'systemctl list-unit-files'
    ],
    'copy': []
}]


def main():
    """ Main program. """
    print("Fetching Kubernetes deployment status...")
    k = K8sDiags()
    k.save_json()
    k.k8s_node_checks()
    k.k8s_event_checks()

    print("Running diagnostic commands on pods...")
    for item in POD_DIAGS:
        print(f"Running tests for: {item['name']}")
        results = k.run_by_label(item)
        print("--------- done ----------")
    print("creating tar archive...")
    results = k.archive()
    print(f"Archive is in {results['tar_file']}")


if __name__ == '__main__':
    main()

# TODO

# queries for status alarms, like restartCount > 0.

# load a config file to read in additional pod_diags (like for debugging
# a specific problem at customer site)
