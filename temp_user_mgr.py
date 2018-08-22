#!/usr/bin/python
# -*- coding: UTF-8 -*-

from shadowsocks import shell, common
from configloader import load_config, get_config
import random
import getopt
import sys
import json
import base64
import hashlib
import requests
import time

try:
    xrange = range
except:
    pass


secret = 'SIQUXETIXMCGZUCKDNFX'

class MuJsonLoader(object):
    def __init__(self):
        self.json = None

    def load(self, path):
        l = "[]"
        try:
            with open(path, 'rb+') as f:
                l = f.read().decode('utf8')
        except:
            pass
        self.json = json.loads(l)

    def save(self, path):
        if self.json is not None:
            output = json.dumps(self.json, sort_keys=True, indent=4, separators=(',', ': '))
            with open(path, 'a'):
                pass
            with open(path, 'rb+') as f:
                f.write(output.encode('utf8'))
                f.truncate()


class MuMgr(object):
    def __init__(self):
        self.config_path = get_config().MUDB_FILE
        try:
            self.server_addr = get_config().SERVER_PUB_ADDR
        except:
            self.server_addr = '127.0.0.1'
        self.data = MuJsonLoader()

        if self.server_addr == '127.0.0.1':
            self.server_addr = self.getipaddr()

    def getipaddr(self, ifname='eth0'):
        import socket
        import struct
        ret = '127.0.0.1'
        try:
            ret = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
        except:
            pass
        if ret == '127.0.0.1':
            try:
                import fcntl
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ret = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
            except:
                pass
        return ret

    def ssrlink(self, user, encode, muid):
        protocol = user.get('protocol', '')
        obfs = user.get('obfs', '')
        protocol = protocol.replace("_compatible", "")
        obfs = obfs.replace("_compatible", "")
        protocol_param = ''
        if muid is not None:
            protocol_param_ = user.get('protocol_param', '')
            param = protocol_param_.split('#')
            if len(param) == 2:
                for row in self.data.json:
                    if int(row['port']) == muid:
                        param = str(muid) + ':' + row['passwd']
                        protocol_param = '/?protoparam=' + common.to_str(
                            base64.urlsafe_b64encode(common.to_bytes(param))).replace("=", "")
                        break
        link = ("%s:%s:%s:%s:%s:%s" % (self.server_addr, user['port'], protocol, user['method'], obfs,
                                       common.to_str(base64.urlsafe_b64encode(common.to_bytes(user['passwd']))).replace(
                                           "=", ""))) + protocol_param
        return "ssr://" + (
        encode and common.to_str(base64.urlsafe_b64encode(common.to_bytes(link))).replace("=", "") or link)

    def userinfo(self, user, muid=None):
        ret = ""
        key_list = ['user', 'port', 'method', 'passwd', 'protocol', 'protocol_param', 'obfs', 'obfs_param',
                    'transfer_enable', 'u', 'd']
        for key in sorted(user):
            if key not in key_list:
                key_list.append(key)
        for key in key_list:
            if key in ['enable'] or key not in user:
                continue
            ret += '\n'
            if (muid is not None) and (key in ['protocol_param']):
                for row in self.data.json:
                    if int(row['port']) == muid:
                        ret += "    %s : %s" % (key, str(muid) + ':' + row['passwd'])
                        break
            elif key in ['transfer_enable', 'u', 'd']:
                if muid is not None:
                    for row in self.data.json:
                        if int(row['port']) == muid:
                            val = row[key]
                            break
                else:
                    val = user[key]
                if val / 1024 < 4:
                    ret += "    %s : %s" % (key, val)
                elif val / 1024 ** 2 < 4:
                    val /= float(1024)
                    ret += "    %s : %s  K Bytes" % (key, val)
                elif val / 1024 ** 3 < 4:
                    val /= float(1024 ** 2)
                    ret += "    %s : %s  M Bytes" % (key, val)
                else:
                    val /= float(1024 ** 3)
                    ret += "    %s : %s  G Bytes" % (key, val)
            else:
                ret += "    %s : %s" % (key, user[key])
        ret += "\n    " + self.ssrlink(user, False, muid)
        ret += "\n    " + self.ssrlink(user, True, muid)
        return ret

    def rand_pass(self):
        return ''.join(
            [random.choice('''ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~-_=+(){}[]^&%$''') for i in
             range(8)])

    def add(self, user):
        up = {'enable': 1, 'u': 0, 'd': 0, 'method': "aes-256-cfb",
              'protocol': "origin",
              'obfs': "plain",
              'transfer_enable': 9007199254740992}
        up['passwd'] = self.rand_pass()
        up.update(user)

        self.data.load(self.config_path)
        for row in self.data.json:
            match = False
            if 'user' in user and row['user'] == user['user']:
                match = True
            if 'port' in user and row['port'] == user['port']:
                match = True
            if match:
                row.update(user)
                print("### update user info %s" % self.userinfo(user))
                self.data.save(self.config_path)
                return
        self.data.json.append(up)
        print("### add user info %s" % self.userinfo(up))
        self.data.save(self.config_path)

    def edit(self, user):
        self.data.load(self.config_path)
        for row in self.data.json:
            match = True
            if 'user' in user and row['user'] != user['user']:
                match = False
            if 'port' in user and row['port'] != user['port']:
                match = False
            if match:
                print("edit user [%s]" % (row['user'],))
                row.update(user)
                print("### new user info %s" % self.userinfo(row))
                break
        self.data.save(self.config_path)

    def clear_ud(self, user):
        up = {'u': 0, 'd': 0}
        self.data.load(self.config_path)
        for row in self.data.json:
            match = True
            if 'user' in user and row['user'] != user['user']:
                match = False
            if 'port' in user and row['port'] != user['port']:
                match = False
            if match:
                row.update(up)
                print("clear user [%s]" % row['user'])
        self.data.save(self.config_path)

    def list_mutli_user_json(self):
        self.data.load(self.config_path)
        print(self.data.json)

    def add_user_by_num(self, userinfos):
        up = {'enable': 1, 'u': 0, 'd': 0, 'method': "aes-256-cfb",
              'protocol': "origin",
              'obfs': "plain",
              'transfer_enable': 9007199254740992}
        up['passwd'] = self.rand_pass()
        new_users = []
        start_port = 10000
        self.data.load(self.config_path)
        self.data.json = sorted(self.data.json, key=lambda x: x.get('port'))
        if len(self.data.json) > 0:
            start_port = self.data.json[-1].get('port', 9999) + 1

        num = userinfos.get('num', 100)
        api = userinfos.get('api', 'https://c5api.yuanjin.io/nodes')
        manager_address = userinfos.get('manager_address')
        up = {'enable': 1, 'u': 0, 'd': 0, 'method': "aes-256-cfb",
              'protocol': "origin",
              'obfs': "plain",
              'transfer_enable': 9007199254740992}
        old_ports = [i.get('port') for i in self.data.json]
        if start_port + num > 65535:
            print('Can not add new port above 65535')
            sys.exit(1)
        new_users = []
        for port in range(start_port, start_port + num):
            new = up.copy()
            new['passwd'] = self.rand_pass()
            new['user'] = str(port)
            new['port'] = port
            self.data.json.append(new)
            new_users.append(new)
        self.data.save(self.config_path)
        for user in new_users:
            user['manager_address'] = manager_address
            user['password'] = user['passwd']
            res = requests.post(api, data=user)
            if res.status_code >= 400:
                print(res.text)
                sys.exit(1)
            time.sleep(0.01)


    def add_mutli_user(self, userinfos):
        up = {'enable': 1, 'u': 0, 'd': 0, 'method': "aes-256-cfb",
              'protocol': "origin",
              'obfs': "plain",
              'transfer_enable': 9007199254740992}
        up['passwd'] = self.rand_pass()
        new_users = []

        self.data.load(self.config_path)
        try:
            new_ports = [i['port'] for i in userinfos]
            error_ports = [row['port'] for row in self.data.json if row['port'] in new_ports]
            if error_ports:
                print("ports already used, %s" % ",".join(map(str, error_ports)))
                sys.exit(1)
            for i in userinfos:
                new = up.copy()
                new.update(i)
                self.data.json.append(new)
                new_users.append(new)
            self.data.save(self.config_path)
            print(new_users)
        except Exception as e:
            print(e)
            sys.exit(1)

    def delete_mutli_user(self, userinfos):
        self.data.load(self.config_path)
        try:
            new_ports = {i['port'] for i in userinfos}
            for i in userinfos:
                if i['port'] in new_ports:
                    userinfos.remove(i)
            self.data.save(self.config_path)
        except Exception as e:
            print(e)
            sys.exit(1)


def _get_config(t, exp):
    base_port = 9900
    span = int((t % 86400) / exp)
    port = base_port + span
    hashmd5 = hashlib.md5()
    hashmd5.update(str(t) + secret)
    password = hashmd5.hexdigest()
    return {
        'enable': 1, 'method': "aes-256-cfb",
        'protocol': "origin",
        'obfs': "plain",
        'transfer_enable': 9007199254740992,
        "user": str(port),
        "port": port,
        "passwd": password
    }


def init(exp):
    exp = int(exp)
    today = int(time.time() / exp) * exp
    manage = MuMgr()
    for i in range(0, int(86400 / exp)):
        t = today + i * exp
        user = _get_config(t, exp)
        manage.add(user)


def main(exp):
    # base_port = 9900
    exp = int(exp)
    now = int(time.time() / exp) * exp - 2 * exp + 86400
    user = _get_config(now, exp)
    manage = MuMgr()
    manage.edit(user)

if __name__ == '__main__':
    if get_config().API_INTERFACE == "yjmudbjson":
        print("Can't use temp_user_mgr.py when API_INTERFACE set yjmudbjson")
        sys.exit(1)
    # TODO Need argv check
    if len(sys.argv) == 3 and sys.argv[1] == 'init':
        init(sys.argv[2])
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print('Need time exp')
        sys.exit(1)


