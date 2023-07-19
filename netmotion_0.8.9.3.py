#!/usr/bin/python3
from queue import Queue
from threading import Thread
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from paramiko.ssh_exception import SSHException
from netmiko.ssh_exception import AuthenticationException
import re
from datetime import datetime, timedelta
from time import time, sleep
import os
from getpass import getpass
import yaml
from ttp import ttp
import sys
from passlib.context import CryptContext

# Global Variables
auth_fail = 0
timeout = 0
ssh_fail = 0
unknown_err = 0


# ------------------------------------------------------------------------------
'''
def ssh_success(server_ip, port=22):
    import socket
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((server_ip, port))
    except Exception:
        return False
    else:
        test_socket.close()
    return True
'''
def encrypt_password(password):
    pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
    )
    return pwd_context.encrypt(password)


# ------------------------------------------------------------------------------
def check_encrypted_password(password, hashed):
    pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
    )
    return pwd_context.verify(password, hashed)


# ------------------------------------------------------------------------------
def reload_system(dev_connect, ip_addr, dev_type, config_yaml):
    import time
    disconnected = False
    now = datetime.now()
    output = ""
    t = time.localtime()
    
    # Set clock before reload to scheduling reload
    # Save running config before reload
    if (dev_type == 'ruckus_fastiron'):
        command = "write mem"
        output = dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4)
        current_datetime = time.strftime("%H:%M:%S %m-%d-%Y", t)
        command = "clock set " + current_datetime
        output = dev_connect.send_command(command)
        print("{} *** {}: Setting the device clock: {} ***".format(now, ip_addr, current_datetime))

    if (dev_type == 'cisco_ios'):
        command = "write mem"
        output = dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4)
        current_datetime = time.strftime("%H:%M:%S %m-%d-%Y", t)
        command = "clock set " + current_datetime
        #output = dev_connect.send_command(command)
        print("{} *** {}: Setting the device clock: {} ***".format(now, ip_addr, current_datetime))

    current_time = time.strftime("%H:%M:%S", t)

    try:
        with open(config_yaml, 'r') as file:
            config_file = yaml.safe_load(file)
    except (IOError):
        output = "Cannot open {} file.".format(config_yaml)
        add_logs(output)

    restricted_times1 = config_file["reload_times"]["time1"]
    restricted_times2 = config_file["reload_times"]["time2"]
    restricted_times3 = config_file["reload_times"]["time3"]
    restricted_times4 = config_file["reload_times"]["time4"]
    reload_at_noon = config_file["reload_times"]["reload_at_noon"]
    reload_at_evening = config_file["reload_times"]["reload_at_evening"]
    reload_time = ""
    if (restricted_times1 < current_time and current_time < restricted_times2):
        #print("{} < {} and {} < {}".format(current_time, restricted_times1, current_time, restricted_times2))
        reload_time = reload_at_noon
    elif (restricted_times3 < current_time and current_time < restricted_times4):
        #print("{} < {} and {} < {}".format(current_time, restricted_times3, current_time, restricted_times4))
        reload_time = reload_at_evening
    else:
        reload_time = "now"

    if (dev_type == 'ruckus_fastiron'):
        if reload_time == "now":
            command = "boot system flash primary yes"
            output += dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4)
            sleep(2)
            host_reachable = ping_success(ip_addr)
            if not host_reachable:
                disconnected = True
                add_logs("***{} is reloading now {} ***".format(ip_addr, reload_time))
        else:
            date = time.strftime("%m-%d-%Y", t)
            command = "reload at " + reload_time + " " + str(date) + " primary"
            output += dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4)
            add_logs("*** {} is scheduled for reload at {} ***".format(ip_addr, reload_time))

    if (dev_type == 'cisco_ios'):
        if reload_time == "now":
            command = "reload"
            output = dev_connect.send_command(command, expect_string=r'confirm]')
            command = '\n'
            output += dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4)
            host_reachable = ping_success(ip_addr)
            if not host_reachable:
                disconnected = True
                add_logs("***{} is reloading now {} ***".format(ip_addr, reload_time))
        else:
            command = "reload at " + reload_time
            output = dev_connect.send_command(command, expect_string=r'confirm]')
            command = '\n'
            output += dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4)
            add_logs("***{} is scheduled for reload at {} ***".format(ip_addr, reload_time))
    return disconnected


# ------------------------------------------------------------------------------
def verify_firmware(dev_connect, ip_addr, dev_type, fw_size, fw_hash):
    success = False
    now = str(datetime.now())
    print("{} *** {}: Please wait while verifying firmware ***".format(now, ip_addr))

    if (dev_type == 'ruckus_fastiron'):

        command = "verify md5 primary"
        output = '[{}]'.format(command)
        output += dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4)

        reg = re.compile(r'\sSize\s=\s(\d+)')
        fw_size_controlled = reg.findall(output)

        reg = re.compile(r'MD5\s(\b.*[a-zA-Z]+.*\b)')
        fw_hash_controlled = reg.findall(output)

        if (int(fw_size) == int(fw_size_controlled[0]) ) and (fw_hash == fw_hash_controlled[0]):
            print("{} *** {}: Firmware verified and OK ***".format(now, ip_addr))
            success = True
        else:
            print("{} *** {}: Firmware verification FAILED ***".format(now, ip_addr))
            success = False

    if (dev_type == 'cisco_ios'):
        command = ""

    return success


# ------------------------------------------------------------------------------
def ensure_free_space(dev_connect, dev_type, fw, boot_fw, fw_size):

    if (dev_type == 'ruckus_fastiron') or (dev_type == 'cisco_ios'):
       command = "show flash"
    
    command_output = dev_connect.send_command_timing(command)

    if (dev_type == 'ruckus_fastiron'):
        reg_fw = re.compile(r'\sSpace\s=\s(\d+)')

    if (dev_type == 'cisco_ios'):
        reg_fw = re.compile(r'\sSpace\s=\s(\d+)')

    space_list = reg_fw.findall(command_output)

    for space in space_list:
        if (int(space) <= 0) or (int(space) <= int(fw_size)):
            return False

    return True


# ------------------------------------------------------------------------------
def check_current_firmware(dev_connect, dev_type, fw, boot_fw):

    command = "show version"
    show_ver = dev_connect.send_command_timing(command)

    if (dev_type == 'ruckus_fastiron'):
        boot_firmware = boot_fw.split('.')[0]
        firmware = fw.split('.')[0]

        if (boot_firmware in show_ver) and (firmware in show_ver):
            return True

    if (dev_type == 'cisco_ios'):
        if (fw in show_ver):
            return True

    return False


# ------------------------------------------------------------------------------
def firmware_update(dev_connect, net_device, tftp_srv, config_yaml, images_yaml, switch_model):
    '''
    network_device = {
        'device_type': device_type,
        'ip': ip_address,
        'username': username,
        'password': password,
        'secret': enablepass,
        'verbose' : False
    }
    '''
    ip_addr = net_device['ip']
    dev_type = net_device['device_type']
    dev_connect.send_command_expect('\n', expect_string=r'#', delay_factor=2)
    dev_connect.clear_buffer()
    output = ''
    success = False
    boot_success = True
    now = str(datetime.now())
    try:
        with open(images_yaml, 'r') as file:
            image = yaml.safe_load(file)
    except (IOError):
        output = "Cannot open {} file.".format(images_yaml)
        add_logs(output)

    if (dev_type == 'ruckus_fastiron'):
        if ("ICX6450" in switch_model):
            device_model = "ICX6450"

        if ("P" in switch_model):
            device_poe = True

        if ("ICX6650" in switch_model):
            device_model = "ICX6650"

        firmware = image[device_model]['filename']
        boot_fw = image[device_model]['boot']
        fw_path = image[device_model]['path']
        fw_size = int(image[device_model]['size'])
        fw_hash = image[device_model]['hash']

    if (dev_type == 'cisco_ios'):
        if ("C2960X" in switch_model):
            device_model = "C2960X"

        firmware = image[device_model]['filename']
        boot_fw = image[device_model]['boot']
        fw_path = image[device_model]['path']
        fw_size = int(image[device_model]['size'])
        fw_hash = image[device_model]['hash']

    fw_installed = check_current_firmware(dev_connect, dev_type, firmware, boot_fw)

    # To force firmware install
    # fw_installed = False

    if not fw_installed:
        free_space = ensure_free_space(dev_connect, dev_type, firmware, boot_fw, fw_size)

        if free_space:
            if (dev_type == 'ruckus_fastiron'):
                if (device_poe):
                    add_logs("*** {}: Some devices are POE in stack. You must manually upgrade POE firmware because of compatibility. ***".format(ip_addr))
                command = "copy tftp flash {} {}/{} bootrom".format(tftp_srv, fw_path, boot_fw)
                print("{} *** {}: Loading BOOTROM ***".format(now, ip_addr))
                output = dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4, max_loops=1000)
                if "TFTP to Flash Done" in output:
                    print("{} *** {}: BOOTROM  Upgrade COMPLETED ***".format(now, ip_addr))
                else:
                    print("{} *** {}: BOOTROM Upgrade FAILED ***".format(now, ip_addr))
                    print(" {}".format(output))
                    boot_success = False

                command = "copy tftp flash {} {}/{} primary".format(tftp_srv, fw_path, firmware)
                print("{} *** {}: Loading firmware to primary flash ***".format(now, ip_addr))
                output = dev_connect.send_command_timing(command, strip_prompt=False, strip_command=True, delay_factor=4, max_loops=1000)
                if "TFTP to Flash Done" in output:
                    print("{} *** {}: Firmware Upgrade COMPLETED ***".format(now, ip_addr))
                    success = True
                else:
                    print("{} *** {}: Firmware Upgrade FAILED ***".format(now, ip_addr))
                    print("\n{}".format(output))
            
            # Cisco part now yet ready
            if (dev_type == 'cisco_ios'):
                command = ""
                success = False

            if success and boot_success:
                fw_verified = verify_firmware(dev_connect, ip_addr, dev_type, fw_size, fw_hash)
                if fw_verified:
                    print("{} *** {}: Software verified ***".format(now, ip_addr))
                    reloaded = reload_system(dev_connect, ip_addr, dev_type, config_yaml)
                    if reloaded:
                        print("\n{} *** {}: System reloaded successfuly ***".format(now, ip_addr))
                        sleep(120)
                        dev_connect = connect_device(net_device)
                        checked = check_current_firmware(dev_connect, dev_type, firmware, boot_fw)
                        if checked:
                            success = True
                            add_logs("{} *** {}: firmware successfuly installed ***".format(now, ip_addr))
        else:
            add_logs("*** {}: No space on disk device".format(ip_addr))
    else:
        add_logs("*** {}: Firmware already installed ***".format(ip_addr))
        success = True

    return success


# ------------------------------------------------------------------------------
def print2(output):
    for i in range(len(output), 79):
        output += ' '
    output += '#'
    print(output)


# ------------------------------------------------------------------------------
def ping_success(host_or_ip, packets=1, timeout=1000):
    import platform
    import subprocess
    # The ping command is the same for Windows and Linux, except for the "number of packets" flag.
    if platform.system().lower() == 'windows':
        command = ['ping', '-n', str(packets), '-w', str(timeout), host_or_ip]
        # run parameters: capture output, discard error messages, do not show window
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        return result.returncode == 0 and b'TTL=' in result.stdout
    else:
        command = ['ping', '-c', str(packets), '-w', str(timeout / 1000), host_or_ip]
        # run parameters: discard output and error messages
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0


# ------------------------------------------------------------------------------
def validate_ip_addr(ip_addr):
    import ipaddress
    ip_addr = ip_addr.strip()
    try:
        if ipaddress.ip_address(ip_addr):
            return True
    except (ValueError):
        error_output = '# Invalid IP address: {}'.format(ip_addr)
        add_logs(error_output)
        return False


# ------------------------------------------------------------------------------
def validate_device_type(device_type):
    device_type = device_type.strip()
    if device_type == 'cisco_ios':
        return True
    elif device_type == 'hp_procurve':
        return True
    elif device_type == 'hp_comware':
        return True
    elif device_type == 'ruckus_fastiron':
        return True
    elif device_type == 'juniper':
        return True
    elif device_type == 'enterasys_ssh':
        return True
    elif device_type == 'extreme_exos':
        return True    
    elif device_type == 'extreme_netiron':
        return True
    elif device_type == 'huawei':
        return True
    elif device_type == 'others':
        return True
    else:
        return False


# ------------------------------------------------------------------------------
def add_logs(error_output):
    error_line = '{} {}\n'.format(str(datetime.now()), error_output)
    with open("log/error.log", "a") as f:
        f.write(error_line)
        f.close
    print(error_line)


# ------------------------------------------------------------------------------
def search_in_list(search_list, keyword_to_find):
    for i in range(len(search_list)):
        if search_list[i] == keyword_to_find:
            return True
    return False


# ------------------------------------------------------------------------------
def read_dev_lists(devices_file):
    try:
        with open(devices_file) as f:
            bulk_device_list = f.read().splitlines()

        device_l = []
        # If there are '#' operators, skip these lines
        for device in bulk_device_list:
            if ('#' or '!') not in device:
                device_list = device.split(';')
                if validate_ip_addr(device_list[0].strip()):
                    # First value is ip address
                    ip_addr = device_list[0].strip()

                    if validate_device_type(device_list[-1].strip()):
                        # Last value is device type
                        device_type = device_list[-1].strip()
                        device_l.append((ip_addr, device_type))
    except (IOError):
        error_output = 'Devices file not found ***File: {} ***'.format(devices_file)
        add_logs(error_output)
        exit()

    return device_l


# -----------------------------------------------------------------------------
def copy_run_to_tftp(dev_connect, ip_addr, dev_type, tftp_srv, tftp_conf_dir):

    dev_connect.send_command_expect('\n', expect_string=r'#', delay_factor=2)

    # hostname = dev_connect.find_prompt(-1)
    dev_connect.send_command('\n', expect_string=r'#', delay_factor=2)
    dev_connect.send_command('\n', expect_string=r'#', delay_factor=2)
    dev_connect.clear_buffer()

    filename = "{}-{}".format(ip_addr, datetime.today().strftime('%Y%m%d-%H%M%S'))
    output = '\n' + '-' * 80 + '\n'
    if (dev_type == 'cisco_ios'):
        copy_config = "copy running-config tftp://{}/{}/{}.cfg".format(tftp_srv, tftp_conf_dir, filename)
        output += '[' + copy_config + ']'
        dev_connect.send_command(copy_config, expect_string=r']?', delay_factor=2)
        dev_connect.send_command_timing('\n', delay_factor=2)
        sleep(2)
        return output

    if (dev_type == 'hp_procurve'):
        copy_config = "copy running-config tftp {} /{}/{}.cfg".format(tftp_srv, tftp_conf_dir, filename)
        output += '[' + copy_config + ']'
        dev_connect.send_command(copy_config, expect_string=r'#', delay_factor=2)
        dev_connect.send_command_timing('\n', delay_factor=2)
        sleep(2)
        return output

    if (dev_type == 'ruckus_fastiron'):
        copy_config = "copy running-config tftp {} /{}/{}.cfg".format(tftp_srv, tftp_conf_dir, filename)
        output += '[' + copy_config + ']'
        dev_connect.send_command(copy_config, expect_string=r'#', delay_factor=2)
        dev_connect.send_command_timing('\n', delay_factor=2)
        sleep(2)
        return output


# -----------------------------------------------------------------------------
def get_vendor_info(dev_connect, ip_addr, config):
    '''
        dev_connect = {
            'device_type': device_type,
            'ip': ip_address,
            'username': username,
            'password': password,
            'secret': enablepass,
            'verbose' : False
        }
    '''
    dev_connect.send_command_expect('\n', expect_string=r'#', delay_factor=2)
    hostname = dev_connect.find_prompt()
    # Ensure we are in enable mode and can make changes.
    if "#" not in hostname[-1]:
        dev_connect.enable()

    dev_connect.send_command('\n', expect_string=r'#', delay_factor=2)

    # Just Cisco and Ruckus use show version command
    if dev_connect.device_type == "cisco_ios" or dev_connect.device_type == "ruckus_fastiron":
        show_ver_str = dev_connect.send_command("show version", delay_factor=2)
    sleep(0.5)
    dev_connect.send_command('\n', expect_string=r'#', delay_factor=2)
    dev_connect.clear_buffer()
    show_ver_str2 = show_ver_str
    show_ver_str = show_ver_str.splitlines()

    if dev_connect.device_type == "ruckus_fastiron":
        device_vendor = "Ruckus"
        reg = re.compile(r'ICX\d{2}[a-zA-Z]\d{5}[a-zA-Z].bin')
        device_firmware_lst = reg.findall(show_ver_str2)
        for device_firmware in device_firmware_lst:
            device_firmware = device_firmware.strip()
        # print("Firmware: {}".format(device_firmware))
        # ICX64S08030r.bin
    
        reg = re.compile(r'ICX[aA-zZ0-9_]{1,}\-[0-9]{1,}[aA-zZ0-9_]{1,}\s')
        device_model_lst = reg.findall(show_ver_str2)
        for device_model in device_model_lst:
            device_model = device_model.strip()
            device_model = device_model.split("-")[0]
        # print('Chassis Type: {}'.format(device_model))
        # ICX6450

        device_boot_firmware = ""
        reg = re.compile(r'[a-zA-Z]{3}[0-9]{5}')
        bootrom_lst =  reg.findall(show_ver_str2)
        for device_boot_firmware in bootrom_lst:
            device_boot_firmware = device_boot_firmware.strip()
        # print('Bootrom: {}'.format(device_boot_firmware))
        # kxz1015

        reg = re.compile(r'\#\W\s[a-zA-Z0-9]{1,}')
        # "#: BZU0412K012"
        device_serial_lst = reg.findall(show_ver_str2)
        for device_serial in device_serial_lst:
            device_serial = device_serial.split(':')[1].strip()
        # print('Serial: {}'.format(device_serial))
        # BZU0412K012

    if dev_connect.device_type == "cisco_ios":
        device_vendor = "Cisco"
        # Find Model
        # If device is switch
        reg = re.compile(r'[mM]odel [nN]umber\s{1,}:\s(\S*)')
        device_model = re.search(reg, show_ver_str2)
        if (device_model): 
            device_model = device_model.group(1)
        # print("Model: {}".format(device_model))
        # Model: WS-C2960X-48TS-L

        # Find Firmware
        reg = re.compile(r'[vV]ersion\s*(.+?)[\s|,]')
        device_firmware = re.search(reg, show_ver_str2)
        if (device_firmware):
            device_firmware = device_firmware.group(1) 
        # device_firmware = 15.2(4)E7

        # Serial:
        reg = re.compile(r'.*[bB]oard\sID\s(\w+)')
        device_serial = re.search(reg, show_ver_str2)
        if (device_serial):
            device_serial = device_serial.group(1)
        # print('Serial: {}'.format(serial))
        # Serial: FOC2143T3U8

        # No boot firmware
        device_boot_firmware = ""

    if dev_connect.device_type == "hp_procurve":
        device_vendor = "HPE Procurve"
        get_mib_str = dev_connect.send_command_expect("getmib sysDescr.0", expect_string=r'#', delay_factor=2)
        dev_connect.clear_buffer()
        sleep(1)
        show_info_str = dev_connect.send_command_expect("show system information", expect_string=r"#", delay_factor=2)
        dev_connect.clear_buffer()
        show_info_str = show_info_str.splitlines()

        ### Model ###
        reg = re.compile(r'J[a-zA-Z0-9]{1,6}')
        device_model = re.search(reg, get_mib_str)
        device_model = device_model.group(0)
        # print("Model: {}".format(model))
        # Model: J9280A

        # Procurve 2510 Model: J9280A
        if device_model == 'J9280A':
            reg = re.compile(r'[sS]oftware [rR]evision\s*.(.+?)[\s|,]')
            device_firmware = re.search(reg, show_info_str)
            device_firmware = device_firmware.group(1)
            # print("Firmware version: {}".format(version))
            # Firmware version:  WB.16.09.0009
        else:
            reg = re.compile(r'[sS]oftware [rR]evision\s*.(.+?)[\s|,]')
            device_firmware = re.search(reg, show_info_str)
            device_firmware = device_firmware.group(1)
            # print("Firmware version: {}".format(version))
            # Firmware version:  WB.16.09.0009

        # Serial:
        reg = re.compile(r'[sS]erial [nN]umber\s{1,}:\s(\S*)')
        device_serial = re.search(reg, show_info_str)[0].strip()
        device_serial = device_serial.split(':')[1].strip()
        # print('Serial: {}'.format(device_serial))
        # Serial: SG57FLYSR1

        # No boot firmware
        device_boot_firmware = ""

    if dev_connect.device_type == "Enterasys":
        device_vendor = "Enterasys"
        # No boot firmware
        device_boot_firmware = ""
        show_switch_str = dev_connect.send_command_expect("show switch", expect_string=r'#', delay_factor=2)
        dev_connect.clear_buffer()
        sleep(1)
        with open(config['ttp']['enterasys_sh_switch'], "r") as t:
            template = t.read()
        #print(template) 
        parser = ttp(data=show_switch_str, template=template)
        parser.parse()
        output = parser.result(format="yaml")[0]
        params = yaml.full_load(output)
        device_model = params[0][0]['model_id']
        device_firmware = params[0][0]['firmware_version']
        
        # Serial:
        reg = re.compile(r'[0-9]{10,}')
        device_serial = re.search(reg, show_info_str)[0].strip()
        # print('Serial: {}'.format(device_serial))
        # Serial: 001188021035

    device_dict = {
        ip_addr: {
            'vendor': device_vendor, 'model': device_model, 'firmware': device_firmware,
            'boot_firmware': device_boot_firmware, 'serial': device_serial, 'hostname': hostname
        }
    }

    return device_dict


# -----------------------------------------------------------------------------
def config_worker(q):
    '''
        network_device = {
            'device_type': device_type,
            'ip': ip_address,
            'username': username,
            'password': password,
            'secret': enablepass,
            'verbose' : False
        }
    '''
    import logging

    global auth_fail, timeout, ssh_fail, unknown_err
    now = datetime.now()

    config_file = 'config.yaml'
    images_yaml = 'images.yaml'

    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
    except (IOError):
        output = "Cannot open {} file.".format(config_file)
        add_logs(output)
        sys.exit()

    do_config = False
    if config['run']['do_config']:
        do_config = True

    get_backup = False
    if config['run']['config_backup']:
        get_backup = True

    update_fw = False
    if config['run']['update_firmware']:
        update_fw = True

    while True:

        log_dir = config['server-config']['logging_dir']
        netmotion_err_file = log_dir + '/' + config['log']['err_log']

        logging.basicConfig(filename=netmotion_err_file, level=logging.DEBUG)
        logging.getLogger("netmiko")

        network_device = q.get()
        ip_addr = network_device['ip']
        device_type = network_device['device_type']

        config_dir = config['server-config']['configuration_directory']
        brocade_cmd_f = config_dir + '/' + config['command-files']['brocade_cmd_file']
        brocade_cfg_f = config_dir + '/' + config['command-files']['brocade_cfg_file']

        cisco_cmd_f = config_dir + '/' + config['command-files']['cisco_cmd_file']
        cisco_cfg_f = config_dir + '/' + config['command-files']['cisco_cfg_file']

        hpe_2510_cmd_f = config_dir + '/' + config['command-files']['hpe_2510_cmd_file']
        hpe_2510_cfg_f = config_dir + '/' + config['command-files']['hpe_2510_cfg_file']

        hpe_aruba_cmd_f = config_dir + '/' + config['command-files']['hpe_aruba_cmd_file']
        hpe_aruba_cfg_f = config_dir + '/' + config['command-files']['hpe_aruba_cfg_file']

        switch_inventory_f = config_dir + '/' + config['inventory-files']['switch_inventory_file']

        tftp_srv = config['tftp']['tftp_server']
        tftp_conf_dir = config['tftp']['tftp_config_dir']

        host_reachable = False
        host_reachable = ping_success(ip_addr)
        if (host_reachable):
            try:
                print('# {} ..... OK..... Connecting to device...'.format(ip_addr))
                dev_connect = ConnectHandler(**network_device)
                prompt = dev_connect.find_prompt()
                # Ensure we are in enable mode and can make changes.
                if "#" not in prompt[-1]:
                    dev_connect.enable()
                sleep(1)
                dev_connect.clear_buffer()
            except (AuthenticationException):
                error_output = '# Authentication failed while connecting to {}'.format(ip_addr)
                add_logs(error_output)
                sleep(1)
                auth_fail += 1
                q.task_done()
                continue
            except (NetMikoTimeoutException):
                error_output = '# Timeout to device: {}'.format(ip_addr)
                add_logs(error_output)
                sleep(1)
                timeout += 1
                q.task_done()
                continue
            except (EOFError):
                error_output = '# End of file while attempting device {}'.format(ip_addr)
                add_logs(error_output)
                sleep(1)
                unknown_err += 1
                q.task_done()
                continue
            except (SSHException):
                error_output = '# SSH Issue. Are you sure SSH is enabled? {}'.format(ip_addr)
                add_logs(error_output)
                sleep(1)
                ssh_fail += 1
                q.task_done()
                continue
            except (IOError):
                error_output = '# Search pattern never detected in send_command_expect.==> {}'.format(ip_addr)
                add_logs(error_output)
                sleep(1)
                unknown_err += 1
                q.task_done()
                continue
            except Exception as unknown_error:
                error_output = '# [{}] Some other error: {}'.format(ip_addr, str(unknown_error))
                add_logs(error_output)
                sleep(1)
                unknown_err += 1
                q.task_done()
                continue
        else:
            q.task_done()
            continue

        device_dict = {
            ip_addr: {'vendor': '', 'model': '', 'firmware': '', 'boot_firmware': '', 'serial': ''}
        }

        # Get device brand, model etc..
        device_dict = get_vendor_info(dev_connect, ip_addr, config)

        vendor = device_dict[ip_addr]['vendor']
        switch_model = device_dict[ip_addr]['model']
        firmware = device_dict[ip_addr]['firmware']
        boot_firmware = device_dict[ip_addr]['boot_firmware']
        serial = device_dict[ip_addr]['serial']

        try:
            with open(switch_inventory_f, "a") as f:
                inventory = '{},{},{},{},{},{}\n'.format(ip_addr, vendor, switch_model, serial, firmware, boot_firmware)
                f.write(inventory)
                f.close()
        except (IOError):
            error_output = '# An error occured while writing to {}\n'.format(switch_inventory_f)
            add_logs(error_output)

        if (do_config):
            host_reachable = ping_success(ip_addr)
            output = '\n' + '#' * 80
            output += '\n' + '# IP: {} | Vendor: {} | Model: {} | Serial: {} \n# Boot Firmware: {} | Firmware: {} '.format(ip_addr, vendor, switch_model, serial, boot_firmware, firmware)
            output += '\n' + '#' * 80 + '\n'
            if (vendor == "Brocade"):
                # Commands
                if os.path.isfile(brocade_cmd_f) and os.stat(brocade_cmd_f).st_size != 0:
                    with open(brocade_cmd_f) as f:
                        commands_list = f.read().splitlines()
                    if (host_reachable):
                        dev_connect.send_command_timing('\n', delay_factor=2)
                        for command in commands_list:
                            if ('#' or '!') not in command:
                                output += "[{}]".format(command) + "\n" * 2
                                output += dev_connect.send_command_timing(command, delay_factor=2) + "\n"
                                output += ("-" * 80) + "\n"

                        dev_connect.send_command_timing('\n', delay_factor=2)
                        dev_connect.clear_buffer()
                else:
                    error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, brocade_cmd_f)
                    add_logs(error_output)

                # Configs
                if os.path.isfile(brocade_cfg_f) and os.stat(brocade_cfg_f).st_size != 0:
                    with open(brocade_cfg_f) as f:
                        configs_list = f.read().splitlines()
                    if (host_reachable):
                        dev_connect.send_command_timing('\n', delay_factor=2)
                        output += dev_connect.send_config_set(configs_list, delay_factor=4)
                        dev_connect.send_command_timing('\n', delay_factor=2)
                        sleep(1)
                        # output += dev_connect.send_command_expect('write mem', expect_string=r"#", delay_factor=2)
                        output = dev_connect.save_config()
                        sleep(2)
                        dev_connect.clear_buffer()
                else:
                    error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, brocade_cfg_f)
                    add_logs(error_output)

            if (vendor == "Cisco"):
                if os.path.isfile(cisco_cmd_f) and os.stat(cisco_cmd_f).st_size != 0:
                    with open(cisco_cmd_f) as f:
                        commands_list = f.read().splitlines()
                    if (host_reachable):
                        dev_connect.send_command_timing('\n', delay_factor=2)
                        for command in commands_list:
                            if ('#' or '!') not in command:
                                output += "[{}]".format(command) + "\n" * 2
                                output += dev_connect.send_command_timing(command, delay_factor=2) + "\n"
                                output += ("-" * 80) + "\n"

                        dev_connect.send_command_timing('\n', delay_factor=2)
                        dev_connect.clear_buffer()
                else:
                    error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, cisco_cmd_f)
                    add_logs(error_output)

                # Configs
                if os.path.isfile(cisco_cfg_f) and os.stat(cisco_cfg_f).st_size != 0:
                    with open(cisco_cfg_f) as f:
                        configs_list = f.read().splitlines()
                    if (host_reachable):
                        dev_connect.send_command_timing('\n', delay_factor=2)
                        output += dev_connect.send_config_set(configs_list, delay_factor=4)
                        dev_connect.send_command_timing('\n', delay_factor=2)
                        sleep(1)
                        # output += dev_connect.send_command_timing("write mem", delay_factor=2)
                        output = dev_connect.save_config()
                        sleep(2)
                        dev_connect.clear_buffer()
                else:
                    error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, cisco_cfg_f)
                    add_logs(error_output)

            if (vendor == "HPE"):
                command_ok = False
                if (switch_model == 'J9280A'):
                    # Command File
                    if os.path.isfile(hpe_2510_cmd_f) and os.stat(hpe_2510_cmd_f).st_size != 0:
                        with open(hpe_2510_cmd_f) as f:
                            commands_list = f.read().splitlines()
                        command_ok = True
                    else:
                        error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, hpe_2510_cmd_f)
                        add_logs(error_output)

                    # Config File
                    if os.path.isfile(hpe_2510_cfg_f) and os.stat(hpe_2510_cfg_f).st_size != 0:
                        with open(hpe_2510_cfg_f) as f:
                            configs_list = f.read().splitlines()
                        configs_ok = True
                    else:
                        error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, hpe_2510_cfg_f)
                        add_logs(error_output)

                else:
                    if os.path.isfile(hpe_aruba_cmd_f) and os.stat(hpe_aruba_cmd_f).st_size != 0:
                        with open(hpe_aruba_cmd_f) as f:
                            commands_list = f.read().splitlines()
                        command_ok = True
                    else:
                        error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, hpe_aruba_cmd_f)
                        add_logs(error_output)

                    if os.path.isfile(hpe_aruba_cfg_f) and os.stat(hpe_aruba_cfg_f).st_size != 0:
                        with open(hpe_aruba_cfg_f) as f:
                            configs_list = f.read().splitlines()
                        configs_ok = True
                    else:
                        error_output = '# Error opening file...  {} configurations file {} not found'.format(vendor, hpe_aruba_cfg_f)
                        add_logs(error_output)

                host_reachable = ping_success(ip_addr)
                if (host_reachable and command_ok):
                    dev_connect.send_command_timing('\n', delay_factor=2)
                    for command in commands_list:
                        if ('#' or '!') not in command:
                            output += "[{}]".format(command) + "\n" * 2
                            output += dev_connect.send_command_timing(command, delay_factor=2)
                            output += ("-" * 80) + "\n"

                    dev_connect.clear_buffer()
                    dev_connect.send_command_timing('\n', delay_factor=2)

                if (host_reachable and configs_ok):
                    dev_connect.send_command_timing('\n', delay_factor=2)
                    output += dev_connect.send_config_set(configs_list, delay_factor=4)
                    dev_connect.send_command_timing('\n', delay_factor=2)
                    sleep(1)
                    dev_connect.clear_buffer()

                output += dev_connect.send_command_expect('write mem', expect_string=r"#", delay_factor=2)
                # output = dev_connect.save_config()
                sleep(2)

        if (get_backup):
            output = copy_run_to_tftp(dev_connect, ip_addr, device_type, tftp_srv, tftp_conf_dir)

        if (update_fw):
            if (not get_backup):
                output = copy_run_to_tftp(dev_connect, ip_addr, device_type, tftp_srv, tftp_conf_dir)
            result = firmware_update(dev_connect, network_device, tftp_srv, config_file, images_yaml, switch_model)
            if (not result):
                add_logs("{} *** {}: firmware upgrade failed or not required. You should manually control the device ***".format(now, ip_addr))

        print(output + '\n')
        sleep(1)
        dev_connect.disconnect()
        if q.empty():
            q.task_done()

        # q.task_done()


# -----------------------------------------------------------------------------
def connect_device(net_device):
    ip_addr = net_device['ip']
    reconnect_attempts = 0
    host_reachable = ping_success(ip_addr)

    while (not host_reachable and reconnect_attempts < 4):
        print('\n*** {}: Attempting to reconnect to device ***'.format(ip_addr))
        sleep(30)
        reconnect_attempts = reconnect_attempts + 1
        host_reachable = ping_success(ip_addr)
        if host_reachable:
            pass

        if reconnect_attempts == 4:
            print('{}: Device not reloaded after {} attempts. Stopped retrying.'.format(ip_addr, reconnect_attempts))
            pass

    if host_reachable:
        try:
            dev_connect = ConnectHandler(**net_device)
            prompt = dev_connect.find_prompt()
            # Ensure we are in enable mode and can make changes.
            if "#" not in prompt[-1]:
                dev_connect.enable()
                sleep(1)
                dev_connect.clear_buffer()
        except:
            add_logs("*** {}: Failed to connect. ***".format(ip_addr))

    return dev_connect


# ==============================================================================
# ---- Main: Configuration
# ==============================================================================

def main(config_yaml):

    global auth_fail, timeout, ssh_fail, unknown_err

    try:
        with open(config_yaml, 'r') as file:
            config = yaml.safe_load(file)
    except (IOError):
        output = "Cannot open {} file.".format(config_yaml)
        add_logs(output)

    do_config = False
    if config['run']['do_config']:
        do_config = True

    update_fw = False
    if config['run']['update_firmware']:
        update_fw = True

    if (update_fw and do_config):
        print("*** You cannot update firmware and configure at the same time. Please choose one of them ***")
        sys.exit()

    devices_file = config['server-config']['configuration_directory'] + '/' + config['server-config']['devices_list']

    num_threads = int(config['thread-pools']['num_threads'])
    max_queue = int(config['thread-pools']['max_queue'])
    username = config['credentials']['username'].strip()
    password = config['credentials']['password'].strip()
    enablepass = config['credentials']['enablepass'].strip()

    if username == "":
        print("\n***Username not found*** \n")
        username = input('Username: ')

    if password == "":
        print("\n***Password not found***")
        password = getpass()

    if enablepass == "":
        print('\n***Enable Secret not found***')
        enablepass = getpass("Enable Password: ")

    print('#' * 80)
    device_list = read_dev_lists(devices_file)

    reachable_device = 0
    unreachable_device = 0

    print('#' * 80)
    starting_time = time()

    q = Queue(maxsize=max_queue)
    for i in range(num_threads):
        t = Thread(target=config_worker, args=(q, ))
        t.daemon = True
        t.start()

    for dev in device_list:
        ip_address = dev[0]
        device_type = dev[1]
        # print ('Creating thread for: ', ip_address)
        host_reachable = ping_success(ip_address)

        if (host_reachable):
            if (device_type == 'cisco_ios') or (device_type == 'hp_procurve') or (device_type == 'ruckus_fastiron'):
                network_device = {
                    'device_type': device_type,
                    'ip': ip_address,
                    'username': username,
                    'password': password,
                    'secret': enablepass,
                    'verbose': False
                }

                reachable_device += 1
                q.put(network_device)

        else:
            error_output = '# {} ..... Ping Failed'.format(ip_address)
            add_logs(error_output)
            unreachable_device += 1

    q.join()

    print('#' * 80)
    print2('#--- Total device = {} | Reachable = {} | Unreachable = {}'.format(reachable_device + unreachable_device, reachable_device, unreachable_device))
    print2('#--- Auth Failure = {} | Timeout = {} | SSH Failure = {} | Unknown Error = {}'.format(auth_fail, timeout, ssh_fail, unknown_err))
    print2('#--- TOTAL Configured Device = {} '.format(reachable_device - (auth_fail + timeout + ssh_fail + unknown_err)))
    print2('#--- Elapsed time = {} (h:m:s)'.format(timedelta(seconds=time() - starting_time)))
    print2('#--- (*) Only Brocade, Cisco and HPE (Procurve & Aruba) products are supported')
    print2('#--- © Copyright TrustBT | ozden.sicim@trustbt.com')
    print('#' * 80)

    print2("#--- Oh God it is finally over ")


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    config_file = 'config.yaml'
    main(config_file)