#!/usr/bin/python
# -*- coding: UTF-8 -*-

from shadowsocks import shell, common
from configloader import load_config, get_config
import random
import getopt
import sys
import json
import base64
import requests
import time


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




def print_server_help():
    print('''usage: python mujson_manage.py -a|-d|-e|-c|-l [OPTION]...

Actions:
  -e EDIT              edit a user
  -c CLEAR             set u/d to zero
  -x ADD multi         add/edit multi users
  -y LIST multi        list multi users details
  -z DELETE multi      delete multi users
  -n ADD multi by num  

Options:
  -u USER              the user name
  -p PORT              server port (only this option must be set if add a user)
  -k PASSWORD          password
  -m METHOD            encryption method, default: aes-128-ctr
  -O PROTOCOL          protocol plugin, default: auth_aes128_md5
  -o OBFS              obfs plugin, default: tls1.2_ticket_auth_compatible
  -G PROTOCOL_PARAM    protocol plugin param
  -g OBFS_PARAM        obfs plugin param
  -t TRANSFER          max transfer for G bytes, default: 8388608 (8 PB or 8192 TB)
  -f FORBID            set forbidden ports. Example (ban 1~79 and 81~100): -f "1-79,81-100"
  -i MUID              set sub id to display (only work with -l)
  -r USERINFOS         set multi user infos

General options:
  -h, --help           show this help message and exit
''')


def main():
    shortopts = 'ecxyznu:i:p:k:O:o:G:g:m:t:f:r:h'
    longopts = ['help']
    action = None
    user = {}
    userinfos = []
    fast_set_obfs = {'0': 'plain',
                     '+1': 'http_simple_compatible',
                     '1': 'http_simple',
                     '+2': 'tls1.2_ticket_auth_compatible',
                     '2': 'tls1.2_ticket_auth'}
    fast_set_protocol = {'0': 'origin',
                         '+ota': 'verify_sha1_compatible',
                         'ota': 'verify_sha1',
                         'a1': 'auth_sha1',
                         '+a1': 'auth_sha1_compatible',
                         'a2': 'auth_sha1_v2',
                         '+a2': 'auth_sha1_v2_compatible',
                         'a4': 'auth_sha1_v4',
                         '+a4': 'auth_sha1_v4_compatible',
                         'am': 'auth_aes128_md5',
                         'as': 'auth_aes128_sha1',
                         }
    fast_set_method = {'a0': 'aes-128-cfb',
                       'a1': 'aes-192-cfb',
                       'a2': 'aes-256-cfb',
                       'r': 'rc4-md5',
                       'r6': 'rc4-md5-6',
                       'c': 'chacha20',
                       'ci': 'chacha20-ietf',
                       's': 'salsa20',
                       'b': 'bf-cfb',
                       'm0': 'camellia-128-cfb',
                       'm1': 'camellia-192-cfb',
                       'm2': 'camellia-256-cfb',
                       'a0t': 'aes-128-ctr',
                       'a1t': 'aes-192-ctr',
                       'a2t': 'aes-256-ctr'}
    try:
        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        for key, value in optlist:
            if key == '-e':
                action = 3
            elif key == '-c':
                action = 0
            # ADD mutli user actions
            elif key == '-x':
                action = 5
            elif key == '-z':
                action = 6
            elif key == '-y':
                action = 7
            elif key == '-n':
                action = 8
            elif key == '-r':
                try:
                    userinfos = json.loads(value)
                except Exception as e:
                    print(e)
                    sys.exit(1)
            elif key == '-u':
                user['user'] = value
            elif key == '-i':
                user['muid'] = int(value)
            elif key == '-p':
                user['port'] = int(value)
            elif key == '-k':
                user['passwd'] = value
            elif key == '-o':
                if value in fast_set_obfs:
                    user['obfs'] = fast_set_obfs[value]
                else:
                    user['obfs'] = value
            elif key == '-O':
                if value in fast_set_protocol:
                    user['protocol'] = fast_set_protocol[value]
                else:
                    user['protocol'] = value
            elif key == '-g':
                user['obfs_param'] = value
            elif key == '-G':
                user['protocol_param'] = value
            elif key == '-m':
                if value in fast_set_method:
                    user['method'] = fast_set_method[value]
                else:
                    user['method'] = value
            elif key == '-f':
                user['forbidden_port'] = value
            elif key == '-t':
                val = float(value)
                try:
                    val = int(value)
                except:
                    pass
                user['transfer_enable'] = int(val * 1024) * (1024 ** 2)
            elif key in ('-h', '--help'):
                print_server_help()
                sys.exit(0)
    except getopt.GetoptError as e:
        print(e)
        sys.exit(2)

    manage = MuMgr()
    if action == 0:
        manage.clear_ud(user)
    elif action == 3:
        if 'user' in user or 'port' in user:
            manage.edit(user)
        else:
            print("You have to set the user name or port with -u/-p")
            sys.exit(1)
    elif action == 5:
        manage.add_mutli_user(userinfos)
    elif action == 6:
        manage.delete_mutli_user(userinfos)
    elif action == 7:
        manage.list_mutli_user_json()
    elif action == 8:
        manage.add_user_by_num(userinfos)
    elif action is None:
        print_server_help()


if __name__ == '__main__':
    main()