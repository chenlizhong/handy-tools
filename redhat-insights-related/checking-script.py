#!/usr/bin/env python2

"""
Version 1.0
This script checks the consistency of plugin stuffs among three insights repos
on your local system.
They are insights-plugins, insights-content, insights-playbooks.

How to use this script?
1. Change path for repo directoriesi around Line-25.
2. In top layer of repo insights-playbooks, run #python checking-script.py

How to filter among Logged ERRORs?
  Errors are logged with different error code, like ERR15.
  Using examples:
    # python checking-script.py | grep "^ERR2" | grep -v "^ERR2[1|6]"
    # python checking-script.py | grep "^ERR2" | grep -v "^ERR21" | wc -l

"""

# TODO: Maybe add white-list for some ERR-code after each ERROR is reviewed.


import os
import sys
import re
import copy
import yaml


# TOEDIT:
# For repo directory, please use one type and comment the other one.
#
# TYPE-1: default one
# If all three repos are in one folder, please adjust `WORKING_PATH` only.
WORKING_PATH = "/home/lizhong/work2017"
PLUGIN_PATH = os.path.join(WORKING_PATH,
                           "insights-plugins/telemetry/rules/plugins")
CONTENT_PATH = os.path.join(WORKING_PATH, "insights-content/content")
PLAYBOOK_PATH = os.path.join(WORKING_PATH, "insights-playbooks/playbooks")
#
# TYPE-2:
# If not, three repos are in different folders, please adjust for each one.
#
#  PLUGIN_PATH = os.path.join("",
#                             "insights-plugins/telemetry/rules/plugins")
#  CONTENT_PATH = os.path.join("",
#                              "insights-content/content")
#  PLAYBOOK_PATH = os.path.join("",
#                               "insights-playbooks/playbooks")

RE_ERROR_KEY = r'^ERROR_KEY'

# Directory names only in first layer under "telemetry/rules/plugins".
DOMAIN_LIST = [
    'aws',
    'bonding',
    'ceph',
    'container',
    'database',
    'idm',
    'java',
    'kdump',
    'kernel',
    'networking',
    'non_kernel',
    'oracle',
    'osp',
    'registration',
    'rhev',
    'sap',
    'satellite',
    'security',
    'service',
    'shift',
    'storage',
    'util',
    'webservers'
]


def valid_domain(domains):
    try:
        assert (all((isinstance(d, str) and d in DOMAIN_LIST) for d in domains)
                is True)
    except AssertionError:
        print "Unvalid domain filter. Must be given in a list of domain strings which is subset of the defined DOMAIN_LIST."


def errors_in_content(plugin_c, content_c, domains=[]):
    """
    Compair the plugin repo collection with content repo collection.
    Wrap all the errors into exceptions(list) and return it.

    ERROR_CODES:
        ERR11: A plugin has no content dir.
        ERR12: A non-existent plugin still has content directory in content repo.
        ERR13: A plugin's content is wrong place.
        ERR14: A error-key's content is missing.
        ERR15: A plugin's content has extral error-keys(not exist in plugin).
    """
    valid_domain(domains)
    exceptions = []
    common_plugins = set()
    for p in plugin_c:

        if domains and not any(d in plugin_c[p]['relative_path'] for d in domains):
            continue

        if p not in content_c:
            exceptions.append(
                    "ERR11: Plugin %s in %s has no content dir at all"
                    % (p, plugin_c[p]['relative_path']))
            continue
        common_plugins.add(p)

        pc = plugin_c[p]
        cc = content_c[p]

        if pc["relative_path"] != cc["relative_path"]:
            exceptions.append(
                    "ERR13: Should move %s 's content dir from domain %s to %s"
                    % (p, cc['relative_path'], pc['relative_path']))

        pek = copy.deepcopy(pc['error_keys'])
        cek = set(cc['error_keys'].keys())
        if pek != cek:
            for ek in pek:
                if ek not in cek:
                    exceptions.append(
                            "ERR14: %s %s : content missing error-key: %s"
                            % (p, cc, ek))
                else:
                    cek.remove(ek)
            if cek:
                exceptions.append(
                        "ERR15: %s 's content has extral error-key(s): %s"
                        % (p, cek))

    content_plugins = set(content_c.keys())
    content_extra_plugins = content_plugins - common_plugins
    if content_extra_plugins:
        for p in content_extra_plugins:
            relative_path = content_c[p]["relative_path"]
            # Ignore security content, since insights-plugins repo
            # contains no security rule.
            if relative_path.startswith("security"):
                continue
            if domains and not any(d in relative_path for d in domains):
                continue
            exceptions.append(
                    "ERR12: Content of non-existence plugin %s at %s ."
                    % (p, relative_path))

    return exceptions


def errors_in_playbooks(content_c, playbook_c, domains=[], include_security=True):
    """
    Compair the content repo collection with playbook repo collection.
    Wrap all the errors into exceptions(list) and return it.

    ERROR_CODES:
        ERR21: A plugin has no playbook dir.
        ERR22: A non-existent plugin's content still has playbook directory
               in playbook repo.
        ERR23: A plugin's playbook is wrong place.
        ERR24: A error-key's playbook is missing.
        ERR25: A plugin's playbook has extral error-keys(not exist in content).
        ERR26: A error-key's playbook has unconsist product dir with content.
    """
    valid_domain(domains)
    exceptions = []
    common_plugins = set()
    for p in content_c:

        if (not include_security and
                content_c[p]['relative_path'].startswith('security')):
            continue

        if domains and not any(d in content_c[p]['relative_path'] for d in domains):
            continue

        if p not in playbook_c:
            exceptions.append(
                    "ERR21: Plugin %s in %s has no playbook dir at all" %
                    (p, content_c[p]['relative_path']))
            continue
        common_plugins.add(p)

        cc = content_c[p]
        pbc = playbook_c[p]

        if pbc["relative_path"] != cc["relative_path"]:
            exceptions.append(
                    "ERR23: Should move %s 's playbook dir from %s to %s" %
                    (p, pbc["relative_path"], cc['relative_path']))

        cek = copy.deepcopy(cc['error_keys'])
        pbek = copy.deepcopy(pbc['error_keys'])
        if pbek != cek:
            for ek in cek:
                if ek not in pbek:
                    exceptions.append(
                            "ERR24: %s %s 's playbooks missing error-key: %s"
                            % (cc["relative_path"], p, ek))
                else:
                    if cek[ek] != pbek[ek]:
                        exceptions.append(
                                "ERR26: Error-key %s %s %s's playbooks has unconsist product dir with content: content repo contain %s ; playbooks repo contain %s"
                                % (cc["relative_path"], p, ek, cek[ek], pbek[ek]))

                    pbek.pop(ek)
            if pbek:
                exceptions.append(
                        "ERR25: %s %s 's playbook has extral error-key(s): %s"
                        % (cc["relative_path"], p, pbek.keys()))

    playbook_plugins = set(playbook_c.keys())
    playbook_extra_plugins = playbook_plugins - common_plugins
    if playbook_extra_plugins:
        for p in playbook_extra_plugins:
            relative_path = playbook_c[p]["relative_path"]
            if not include_security and relative_path.startswith("security"):
                continue
            if domains and not any(d in relative_path for d in domains):
                continue
            exceptions.append(
                    "ERR22: Playbook of plugin %s at %s is not exist anymore in content repo"
                    % (p, relative_path))

    return exceptions


def get_playbook_structure(path):
    playbook_collections = {}
    for root, dirs, files in os.walk(path):
        if dirs:
            continue

        root_split = root.split('/playbooks/')
        if len(root_split) < 2:
            continue
        root_split = root_split[1].split('/')

        if len(root_split) == 4:
            prod_role = root_split[-1]
            ek = root_split[-2]
            plugin_name = root_split[-3]
            domain = '/'.join(root_split[0:-3])
        elif len(root_split) == 3:
            prod_role = "osp_controller"    # for readme playbook does not have the role, set the default.
            ek = root_split[-1]
            plugin_name = root_split[-2]
            domain = '/'.join(root_split[0])
        else:
            continue

        plugin_info = playbook_collections.setdefault(plugin_name, {})
        plugin_info["relative_path"] = domain
        eks = plugin_info.setdefault('error_keys', {})
        prod_role_set = eks.setdefault(ek, set())
        prod_role_set.add(prod_role)

    return playbook_collections


def get_content_structure(path):
    content_collections = {}
    plugin_yaml = {}
    for root, dirs, files in os.walk(path):
        # no retire dir in content repo
        if "metadata.yaml" not in files:
            continue

        root_split = root.split('/content/')
        if len(root_split) < 2:
            continue
        domain_plugin_ek = root_split[1]
        domain_plugin_ek_split = domain_plugin_ek.split('/')
        if len(domain_plugin_ek_split) < 3:
            continue

        ek = domain_plugin_ek_split[-1].strip()
        plugin_name = domain_plugin_ek_split[-2].strip()
        domain = '/'.join(domain_plugin_ek_split[0:-2])
        prod_role = set(dirs)

        # Load yaml files and read prod_role value from them.
        plugin_yaml = os.path.join(root, "../plugin.yaml")
        metadata_yaml = os.path.join(root, "metadata.yaml")
        yaml_info = {}
        if os.path.exists(plugin_yaml):
            try:
                with open(plugin_yaml) as fp:
                    yaml_info.update(yaml.load(fp))
            except:
                print "%s: Failed YAML parsing" % plugin_yaml
                continue
        try:
            with open(metadata_yaml) as fp:
                yaml_info.update(yaml.load(fp))
        except:
            print "%s: Failed YAML parsing" % metadata_yaml
            continue
        prod_code, role = yaml_info.get('product_code'), yaml_info.get('role')
        if prod_code and role:
            prod_role.add(prod_code + '_' + role)
        # End of 'Load yaml files and read prod_role value from them.'

        plugin_info = content_collections.setdefault(plugin_name, {})
        plugin_info["relative_path"] = domain
        eks = plugin_info.setdefault('error_keys', {})
        eks[ek] = prod_role

    return content_collections


def get_plugin_structure(path):
    plugin_collections = {}
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith(".pyc"):
                continue
            if root.endswith("/security"):
                continue
            if root.endswith("/util"):
                continue
            if f == "__init__.py":
                continue

            domain_split = root.split('/plugins/')
            if len(domain_split) < 2:
                continue
            domain = domain_split[1]
            plugin_name = f[:-3]

            error_keys = set()
            try:
                for line in open(os.path.join(root, f), "r"):
                    if re.match(RE_ERROR_KEY, line):
                        error_keys.add(line.split('=')[1].strip('"\' \n'))
                        # TODO: remove the trail #comments .
            except:
                pass

            plugin_collections[plugin_name] = {"relative_path": domain,
                                               "error_keys": error_keys}

    return plugin_collections


def print_plugin_info(plugin_name, plugin_collections={},
                      content_collections={}, playbook_collections={}):
    """
    Using example for debug:
        print_plugin_info('sat_upgrade_miss_last_step',
                          plugin_collections=plugin_collections,
                          content_collections=content_collections)
    """
    if not plugin_name:
        print "Empty value for plugin_name argument."
        return
    print "Print %s related infos -------------------" % plugin_name
    collections = {'PLUGIN': plugin_collections,
                   'CONTENT': content_collections,
                   'PLAYBOOK': playbook_collections}
    for repo in collections:
        info = collections[repo].get(plugin_name, {})
        if info:
            print "Repo %s has following plugin related files:" % repo
            for item in info:
                print item, " : ", info[item]
            print "\n"
        else:
            print "Repo %s has NO such plugin related files." % repo


def print_domain_info(domain_name, plugin_collections={}):
    """
    Using example for debug:
        print_domain_info('satellite',
                          plugin_collections=plugin_collections)
    """
    # TODO: uncomplete valid checking and log messages
    for p, info in plugin_collections.items():
        if info['relative_path'] == domain_name:
            print p
            print info


def print_errors_in(exceptions=[]):
    print "-------------------------------------------------"
    print "\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/"
    for e in exceptions:
        print e
    print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    print "Total: %d error(s)" % len(exceptions)


if __name__ == "__main__":
    # collect data from repos
    plugin_collections = get_plugin_structure(PLUGIN_PATH)
    content_collections = get_content_structure(CONTENT_PATH)
    playbook_collections = get_playbook_structure(PLAYBOOK_PATH)

    # Get errors
    content_exceptions = errors_in_content(plugin_collections, content_collections)
    playbook_exceptions = errors_in_playbooks(content_collections,
                                              playbook_collections,
                                              include_security=False)

    ###################################################################
    # Want to filter for some domains only ?
    # Use the following code to get errors, and change `domains` first.
    ########################################
    # content_exceptions = errors_in_content(plugin_collections,
    #                                        content_collections,
    #                                        domains=['aws', 'rhev'])
    # playbook_exceptions = errors_in_playbooks(content_collections,
    #                                           playbook_collections,
    #                                           domains=['shift', 'container'],
    #                                           include_security=False)

    print "================================================================="
    print "Print ERRORS in content repo diff to plugin repo"
    print_errors_in(content_exceptions)

    print "================================================================="
    print "Print ERRORS in playbook repo diff to content repo"
    print_errors_in(playbook_exceptions)

    sys.exit(1)

# flake8: noqa
