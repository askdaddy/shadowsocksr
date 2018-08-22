import logging
import db_transfer
from shadowsocks import common
from configloader import get_config


class YJMuJsonTransfer(db_transfer.TransferBase):
    def __init__(self):
        super(YJMuJsonTransfer, self).__init__()

    def update_all_user(self, dt_transfer):
        import json
        useage_rows = None

        config_transfer_path = get_config().YJ_MUDB_TRANSFER_FILE
        config_user_config_path = get_config().YJ_MUDB_USER_CONFIG_FILE
        with open(config_transfer_path, 'rb+') as f:
            useage_rows = json.loads(f.read().decode('utf8'))

        with open(config_user_config_path, 'rb+') as user_config_file:
            user_config_json = json.loads(user_config_file.read().decode('utf8'))
        # useage_ports = {row.get("port", 0): [row.get('u', 0), row.get('d', 0)] for row in useage_rows if row.get("port", 0)}
        # new_useage = []
        # for row in user_config_json:
        #     port = row.get('port')
        #     if port and port in dt_transfer:
        #         if port in useage_rows:
        #             new_useage_port = {
        #                 'user': row.get('user', ''),
        #                 'port': port,
        #                 'u': useage_rows[port][0] + dt_transfer[port][0],
        #                 'd': useage_rows[port][1] + dt_transfer[port][1]
        #             }
        #         else:
        #             new_useage_port = {
        #                 'user': row.get('user', ''),
        #                 'port': port,
        #                 'u': dt_transfer[port][0],
        #                 'd': dt_transfer[port][1]
        #             }
        #         new_useage.append(new_useage_port)
        for row in user_config_json:
            port = row.get('port')
            if port and port in dt_transfer:
                if str(port) in useage_rows:
                    useage_rows[str(port)]['user'] = row.get('user', '')
                    useage_rows[str(port)]['u'] += dt_transfer[port][0]
                    useage_rows[str(port)]['d'] += dt_transfer[port][1]
                else:
                    useage_rows[str(port)] = {
                        'user': row.get('user', ''),
                        'u': dt_transfer[port][0],
                        'd': dt_transfer[port][1]
                    }

        if useage_rows:
            output = json.dumps(useage_rows, sort_keys=True, indent=4, separators=(',', ': '))
            with open(config_transfer_path, 'r+') as f:
                f.write(output)
                f.truncate()
        return dt_transfer

    def pull_db_all_user(self):
        """
        common_json:
        {
            "method": "aes-256-cfb",
            "obfs": "plain",
            "protocol": "origin",
            "transfer_enable": 9007199254740992,
        }
        transfer_json:
        {
            16899: {
                "d": 0,
                "u": 0,
                "user": "16899"
            }
        }

        user_config_json:
        [
            {
                "enable": 1,
                "passwd": "f6)rc]aN",
                "port": 16899,
                "user": "16899"
            }
        ]
        :return:
        """
        import json
        rows = None

        config_user_config_path = get_config().YJ_MUDB_USER_CONFIG_FILE
        config_transfer_path = get_config().YJ_MUDB_TRANSFER_FILE
        config_common_path = get_config().YJ_MUDB_COMMON_FILE

        with open(config_common_path, 'rb+') as common_file:
            common_json = json.loads(common_file.read().decode('utf8'))

        with open(config_transfer_path, 'rb+') as transfer_file:
            transfer_json = json.loads(transfer_file.read().decode('utf8'))

        with open(config_user_config_path, 'rb+') as user_config_file:
            rows = json.loads(user_config_file.read().decode('utf8'))

        for user in rows:
            user.update(common_json)
            if user.get('port', 0) in transfer_json:
                user.update(transfer_json[user.get('port', 0)])
            else:
                user.update({'u': 0, 'd': 0})

        for row in rows:
            try:
                if 'forbidden_ip' in row:
                    row['forbidden_ip'] = common.IPNetwork(row['forbidden_ip'])
            except Exception as e:
                logging.error(e)
            try:
                if 'forbidden_port' in row:
                    row['forbidden_port'] = common.PortRange(row['forbidden_port'])
            except Exception as e:
                logging.error(e)

        if not rows:
            logging.warn('no user in json file')
        return rows
