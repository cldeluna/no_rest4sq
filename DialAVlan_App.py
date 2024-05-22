#!/usr/bin/python -tt
# Project: prefect_intro
# Filename: DialAVlan_App.py
# claudiadeluna
# PyCharm

from __future__ import absolute_import, division, print_function

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "5/17/24"
__copyright__ = "Copyright (c) 2023 Claudia"
__license__ = "Python"

import streamlit as st
import socket
import re
import os
import sys
import time
import netaddr
import pandas as pd
import requests
import datetime
import netmiko
import dotenv
import socket


def try_sq_rest_call_http(
    uri_path,
    url_options,
    protocol="http",
    port="8000",
    api_access_token="496157e6e869ef7f3d6ecb24a6f6d847b224ee4f",
    server="10.1.10.47",
):
    """_summary_
    SuzieQ API REST Call in a Try/Except block
    """
    API_ACCESS_TOKEN = api_access_token
    API_ENDPOINT = server

    url = f"{protocol}://{API_ENDPOINT}:{port}{uri_path}?{url_options}&access_token={API_ACCESS_TOKEN}"

    # Send API request, return as JSON
    # Initialize
    response = dict()
    try:
        response = requests.get(url).json()
    except Exception as e:
        st.error(
            "Connection to SuzieQ REST API Failed.  Please confirm the REST API is running!"
        )
        st.text(e)
        # st.stop()
        response = False

    return response


def find_vlans_in_namespace(namespace):

    ns_vlan_bool = False

    # List of Vlans we don't care about
    dont_care_vlans = [1002, 1003, 1004, 1005]

    URI_PATH = "/api/v2/vlan/show"
    URL_OPTIONS = f"namespace={namespace}&view=latest&columns=default"

    sq_api_response_vlan = try_sq_rest_call_http(URI_PATH, URL_OPTIONS)

    df = pd.DataFrame(sq_api_response_vlan)
    # Drop unsupported Vlans
    df = df[df["state"] != "unsupported"]

    # Drop the hostname column
    df.drop("hostname", axis=1, inplace=True)

    # Get Unique dataframe
    df.drop_duplicates(subset=["vlan"], keep="last", inplace=True)
    df["vlan"] = df["vlan"].astype(int)

    if sq_api_response_vlan:
        ns_vlan_bool = True
    else:
        st.error(f"Error getting Vlans in namespace")
        sq_api_response_vlan = []
        df = pd.DataFrame()

    return ns_vlan_bool, df, sq_api_response_vlan


def find_vlans_on_switch(switch):

    URI_PATH = "/api/v2/vlan/show"
    URL_OPTIONS = f"hostname={switch}&view=latest&columns=default"

    sq_api_response = try_sq_rest_call_http(URI_PATH, URL_OPTIONS)

    # http://10.1.10.47:8000/api/v2/vlan/show?hostname=indian-ocean-sw01&view=latest&columns=default&state=active&access_token=496157e6e869ef7f3d6ecb24a6f6d847b224ee4f

    if sq_api_response:
        vlan_configured_on_sw = True
    else:
        st.error(f"Failed to get all Vlans on switch {switch}")
        sq_api_response = []

    return sq_api_response


def find_vlan_on_switch(vlanx, switch):
    vlan_configured_on_sw = False

    URI_PATH = "/api/v2/vlan/show"
    URL_OPTIONS = f"hostname={switch}&view=latest&columns=default&vlan={vlanx}"

    sq_api_response_vlan = try_sq_rest_call_http(URI_PATH, URL_OPTIONS)

    if sq_api_response_vlan:
        vlan_configured_on_sw = True
    else:
        st.error(f"Vlan {vlanx} is not configured on switch {switch}")
        sq_api_response_vlan = []
        vlan_configured_on_sw = False

    URL_OPTIONS = f"hostname={switch}&view=latest&columns=default&state=active"

    sq_api_response_vlan_allvlans = try_sq_rest_call_http(URI_PATH, URL_OPTIONS)

    # http://10.1.10.47:8000/api/v2/vlan/show?hostname=indian-ocean-sw01&view=latest&columns=default&state=active&access_token=496157e6e869ef7f3d6ecb24a6f6d847b224ee4f

    if sq_api_response_vlan_allvlans:
        pass
    else:
        st.error(f"Failed to get all Vlans on switch {switch}")
        sq_api_response_vlan_allvlans = []

    return vlan_configured_on_sw, sq_api_response_vlan, sq_api_response_vlan_allvlans


def network_find(ipx, view="latest"):

    # http://10.1.10.47:8000/api/v2/network/find?columns=default&view=latest&address=203.0.113.45&access_token=496157e6e869ef7f3d6ecb24a6f6d847b224ee4f

    URI_PATH = "/api/v2/network/find"
    URL_OPTIONS = f"address={ipx.strip()}&view={view}&columns=default&"

    sq_api_response = try_sq_rest_call_http(URI_PATH, URL_OPTIONS)

    return sq_api_response


def get_oui(mac):
    """
    Get MAC Vendor OUI from netaddr....good if you don't have internet access.
    :param mac:
    :return:
    """

    try:
        # Turn the provided mac into a netaddr EUI object
        maco = netaddr.EUI(mac)
        # Get the OUI attribute from the mac object
        macf = maco.oui.registration().org
    except netaddr.core.NotRegisteredError:
        # No information in Vendor OUI table
        macf = "Not available"
    except netaddr.core.AddrFormatError:
        # Incomplete - return an all zeros mac
        macf = "00:00:00:00:00:00"

    return macf


def load_req_dict():
    req_dict = {
        "Where is the device?": False,
        "Is the device on the network now?": False,
        # "Where has the device been?": False,
        "What is its MAC?": False,
        "What is the Vendor OUI of the MAC?": False,
        "What is its current vlan?": False,
        "What switch is it on?": False,
        "What user port is it on?": False,
        "What is the new vlan?": False,
        # "Is the new vlan a valid vlan for the location?": False,
        "Is the new vlan configured on the switch?": False,
        # "Has it been moving around?": False,
    }

    return req_dict


def epoch_to_ts(tx):
    epoch_time = int(tx / 1000)  # Replace with your epoch time
    new_ts = pd.to_datetime(datetime.datetime.fromtimestamp(epoch_time).strftime("%c"))

    # try:
    #     dt_object = datetime.utcfromtimestamp(epoch_time)
    #     formatted_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')
    #     # new_ts = datetime.datetime.fromtimestamp(tx).strftime('%Y-%m-%d %H:%M:%S')
    #     new_ts = formatted_time
    #     st.text(new_ts)
    # except:
    #     new_ts = ""

    return new_ts


def display_requirements(
    display_header="####  Device Checks", req_dict=load_req_dict()
):
    """
    This function takes in a dictionary where the keys are the checks or questions and the values are
    True if we have the information (we have completed the check)
    False if we don't (we have not completed that check)
    """

    check_passed_icon = ":white_check_mark:"
    check_failed_icon = ":white_large_square:"

    # req_dict = load_req_dict()

    if display_header:
        st.markdown("####  Device Checks")

    for check, check_state in req_dict.items():
        if check_state:
            icon = check_passed_icon
        else:
            icon = check_failed_icon

        st.write(f"{icon} {check}")


# ------------------------------ FUNCTIONS TO CONNECT TO NETWORK DEVICES -------------------------
def conn_netmiko(devd):
    dev_cn = ""
    lgin_suc = False

    prot = "SSH"

    try:
        dev_cn = netmiko.ConnectHandler(**devd)
        lgin_suc = True

    except netmiko.NetMikoAuthenticationException:
        st.write(
            f"NetMikoAuthenticationException: Device failed {prot} Authentication with username {devd['username']}"
        )
        lgin_suc = False

    except (EOFError, netmiko.NetMikoTimeoutException):
        st.write("SSH is not enabled for this device.")
        lgin_suc = False

    except Exception as e:
        st.write(
            "\tGeneral Exception: ERROR!:"
            + str(sys.exc_info()[0])
            + "==>"
            + str(sys.exc_info()[1])
        )
        st.write(str(e))
        lgin_suc = False

    return dev_cn, lgin_suc


def create_devobj(dev, auth_timeout=20, session_log=False, debug=False):
    """
        dev = {
        'device_type': 'cisco_nxos',
        'ip' : 'sbx-nxos-mgmt.cisco.com',
        'username' : user,
        'password' : pwd,
        'secret' : sec,
        'port' : 8181,
        "fast_cli": False,
    }
    """

    dotenv.load_dotenv()
    dev_obj = {}
    if debug:
        st.write(os.environ)

    if "INET_USR" in os.environ.keys():
        usr = os.environ["INET_USR"]
    else:
        usr = ""
    if "INET_PWD" in os.environ.keys():
        pwd = os.environ["INET_PWD"]
    else:
        pwd = ""

    dev_obj.update({"ip": dev.strip()})
    dev_obj.update({"username": usr.strip()})
    dev_obj.update({"password": pwd.strip()})
    dev_obj.update({"secret": pwd.strip()})
    dev_obj.update({"port": 22})
    dev_obj.update({"auth_timeout": auth_timeout})
    # autodetect
    dev_obj.update({"device_type": "cisco_xe"})
    if session_log:
        dev_obj.update({"session_log": "netmiko_session_log.txt"})

    return dev_obj


def send_netmiko_commands(conn, hostnm, cmds, method="command", cfgmode_bool=False):
    """
    Function to send commands via a netmiko connection
    :param conn: existing netmiko connection passed to function
    :param hostnm: hostname of device used to find the configuration file which should contain the hostname
    :param cmds: if method is "command" this is a list of commands, if method is "from_file" this should be empty
    :param method: "command" if the connections is going to use the command method, "config_set"  if using the file
    method - this option uses the filelist information
    :param find_file_bool:
        True if the function should try to find the corresponding configuration file based on hostname
        False if passing a specific configuration file into filelist
    :param cfgmode_bool:
        True if connection should be in config mode - used for configuring device
        False if connection should NOT be in config mode - used for show commands
    :return: output of the selected netmiko command

    """

    # initialize the output variable
    cfgoutput = ""

    if not conn.check_config_mode() and cfgmode_bool:
        conn.config_mode()

    if cfgmode_bool:
        if conn.check_config_mode():
            if method == "command":
                for cmd in cmds:
                    cfgoutput += conn.send_command(
                        cmd, strip_prompt=False, strip_command=False
                    )
            elif method == "config_set":
                cfgoutput = conn.send_config_set(cmds)
                st.text(cfgoutput)

    else:
        # Great for show commands
        if method == "command":
            for cmd in cmds:
                cfgoutput += conn.send_command(
                    cmd, strip_prompt=False, strip_command=False
                )

    return cfgoutput


# ------------------------------------------------------------------------------------------------
def main():

    # SuzieQ Version
    # Set to true if using Enterprise Versioin
    enterprise = False

    # Use the full page instead of a narrow central column
    st.set_page_config(layout="wide")

    with st.sidebar:
        st.image(
            "images/dial_shutterstock_1638201142.jpg",
            caption="Dial-a-Vlan App",
            width=200,
        )

    st.title("Dial-a-Vlan App")

    st.image(
        "images/dial_shutterstock_1638201142.jpg", caption="Dial-a-Vlan App", width=800
    )

    display_requirements()

    # Initialize Session State for Streamlit
    dev_info_dict = {"new_vlan": ""}
    if "dev_info_dict" not in st.session_state:
        st.session_state["dev_info_dict"] = dev_info_dict

    st.markdown("---")
    st.subheader(
        f"Enter the Fully Qualified DNS Name of the device you want to find and move"
    )
    val = "asus-pc.us.uwaco.net"
    dev_fqdn = st.text_input("Enter Device FQDN: ", value="www.jpl.nasa.gov")

    st.markdown("---")

    with st.form(key="Dia-a-Vlan"):

        # -------------------------------- GET DEVICE DETAILS  -------------------------------------
        label = f"Find {dev_fqdn}"
        check_option = st.form_submit_button(label=label)

        if check_option and dev_fqdn:

            try:
                x = socket.gethostbyaddr(dev_fqdn)
            except:
                st.error(
                    "Problem getting IP from FQDN. Cannot proceed. Please check FQDN"
                )
                st.stop()
            name_to_ip = x[2]
            dev_ip = name_to_ip[0]
            st.write(f"{dev_fqdn} resolves to IP {name_to_ip[0]}")

            # Dictionary of requirement or check and True/False
            req_dict = load_req_dict()

            # Details response
            resp = network_find(dev_ip)

            # resp_all = network_find(dev_ip, view="all")
            #
            # all_df = pd.DataFrame(resp_all)
            # all_df = all_df[all_df["ifname"].str.contains("GigabitEthernet\d\/0\/\d{1,2}")]
            # all_df['timestamp'] = all_df['timestamp'].apply(epoch_to_ts)
            # st.write(all_df)

            # We want the response to be a list of dictionaries
            if resp and type(resp) == list:
                if len(resp) == 1:

                    # "Is the device on the network now?"
                    st.success(f":thumbsup: Device {dev_fqdn} Found on Network!")
                    req_dict.update({"Is the device on the network now?": True})

                    # "Where is the device?"
                    namespace = resp[0]["namespace"]
                    req_dict.update({"Where is the device?": True})

                    # "What switch is it on?"
                    sw = resp[0]["hostname"]
                    req_dict.update({"What switch is it on?": True})

                    # "What is its MAC?"
                    mac = resp[0]["macaddr"]
                    req_dict.update({"What is its MAC?": True})

                    # "What is its current vlan?"
                    vlan = resp[0]["vlan"]
                    req_dict.update({"What is its current vlan?": True})

                    # "What user port is it on?"
                    ifname = resp[0]["ifname"]
                    # Make sure the device is on a user port and not an SVI or uplink interface or port channel
                    user_ifname = r"GigabitEthernet\d\/0\/\d{1,2}"
                    if re.search(user_ifname, ifname):
                        req_dict.update({"What user port is it on?": True})
                        user_port_found = True
                    else:
                        st.error(
                            f"While device {dev_fqdn} seems to be on the network, the actual interface its connected to cannot be determined."
                        )
                        req_dict.update({"What user port is it on?": False})
                        user_port_found = False

                    dev_info_dict = resp[0].copy()
                    dev_info_dict.update({"on_net_now": True})

                    st.write(f"Device: {name_to_ip[0]}")
                    st.write(f"Location: {namespace}")
                    st.write(f"Mac: {mac}")

                    # "What is the Vendor OUI of the MAC?"
                    vendor_oui = get_oui(mac)
                    st.write(f"Vendor OUI: {vendor_oui}")
                    dev_info_dict.update({"vendor_oui": vendor_oui})
                    req_dict.update({"What is the Vendor OUI of the MAC?": True})

                    st.write(f"Switch {sw} Interface {ifname}")
                    st.write(f"Current Vlan is {vlan}")

                    # Get all the vlans at the campus
                    vlans_on_sw = find_vlans_on_switch(sw)

                    df = pd.DataFrame.from_dict(vlans_on_sw, orient="columns")
                    df = df[df["state"] != "unsupported"]
                    df = df[df["vlan"] != 1]

                    df["vlan"] = df["vlan"].astype(str)
                    df.drop(columns=["timestamp"], inplace=True)
                    df = df[
                        [
                            "namespace",
                            "hostname",
                            "vlan",
                            "vlanName",
                            "state",
                            "interfaces",
                        ]
                    ]

                    dev_info_dict.update({"df": df})
                    dev_info_dict.update({"device_fqdn": dev_fqdn})
                    dev_info_dict.update({"requirement_dict": req_dict})
                    dev_info_dict.update({"new_vlan": req_dict})
                    st.session_state["dev_info_dict"] = dev_info_dict

                    if not user_port_found:
                        st.error("Cannot proceed without a user port.")
                        st.stop()

                else:
                    st.error(f"Multiple records. Aborting!")
                    st.write(resp)
                    st.stop()

            else:
                st.error(
                    f"Device {dev_fqdn} with ip {dev_ip} cannot be located on the network."
                )
                st.write(
                    "*Please make sure the device is connected to the network on the desired jack/port.*"
                )
                st.stop()

        st.markdown("---")

        # -------------------------------- MOVE TO WHICH VLAN -------------------------------------
        label = f"Select new vlan for the port"
        check_option = st.form_submit_button(label=label)

        if check_option and st.session_state["dev_info_dict"]["new_vlan"]:

            # Load the state data into a dictionary
            dev_info_dict = st.session_state["dev_info_dict"]

            # Pull out the values we need for easy reference
            namespace = dev_info_dict["namespace"]
            device_fqdn = dev_info_dict["device_fqdn"]
            sw = dev_info_dict["hostname"]
            ifname = dev_info_dict["ifname"]
            vrf = dev_info_dict["vrf"]
            vlan = dev_info_dict["vlan"]

            st.markdown(f"### Vlans Configured at Location {namespace}")

            ns_vlan_bool, filtered_vlan_df, sq_api_response_vlan = (
                find_vlans_in_namespace(namespace)
            )
            filtered_vlan_df.drop(columns=["timestamp"], inplace=True)
            filtered_vlan_df = filtered_vlan_df[
                [
                    "namespace",
                    "vlan",
                    "vlanName",
                    "state",
                    "interfaces",
                ]
            ]
            st.write(filtered_vlan_df)

            st.subheader(f"Select new vlan for device {device_fqdn}:")
            add_vlan = st.selectbox(
                label="Select Vlan",
                options=list(filtered_vlan_df["vlan"]),
                index=None,
            )

            dev_info_dict.update({"new_vlan": add_vlan})
            dev_info_dict.update({"site_filtered_vlan_df": filtered_vlan_df})
            st.session_state["dev_info_dict"] = dev_info_dict

            if add_vlan:

                # "What is the new vlan?"
                action = f"Requesting Device {device_fqdn} on switch {sw} port {ifname} (vrf {vrf}) move from current vlan {vlan} to vlan {add_vlan}. "
                st.success(action)

                st.info(
                    f"Click [{label}] Button To Update from {add_vlan} to Another Vlan"
                )

                dev_info_dict.update({"action": action})

                st.session_state["dev_info_dict"] = dev_info_dict
            else:
                if not add_vlan:
                    st.info(f"Click [{label}] Button To Set Vlan")

        st.markdown("---")

        # -------------------------------- FINAL CHECKS -------------------------------------

        if st.session_state["dev_info_dict"]["new_vlan"]:

            label = f"Check Requirements"
            check_option = st.form_submit_button(label=label)

            dev_info_dict = st.session_state["dev_info_dict"]

            # Dictionary of requirement or check and True/False
            req_dict = st.session_state["dev_info_dict"]["requirement_dict"]

            # st.write(dev_info_dict['new_vlan'])
            if check_option and dev_info_dict["new_vlan"]:

                dev_info_dict = st.session_state["dev_info_dict"]

                # st.write(dev_info_dict)
                req_dict.update({"What is the new vlan?": True})

                device_fqdn = dev_info_dict["device_fqdn"]
                sw = dev_info_dict["hostname"]
                ifname = dev_info_dict["ifname"]
                vrf = dev_info_dict["vrf"]
                vlan = str(dev_info_dict["vlan"])
                new_vlan = str(dev_info_dict["new_vlan"])
                mac = netaddr.EUI(dev_info_dict["macaddr"])
                # Getting the MAC in Cisco Triple Hex for final check - is the MAC in the ARP table?
                mac_cisco = netaddr.EUI(
                    dev_info_dict["macaddr"], dialect=netaddr.mac_cisco
                )

                df = dev_info_dict["df"]

                st.write(f"Current vlan {vlan}")
                current_df = df[df["vlan"] == vlan]
                st.write(current_df)

                st.write(f"Requested Vlan {new_vlan}")
                new_df = df[df["vlan"] == new_vlan]
                if not new_df.empty:
                    st.write(new_df)
                else:
                    st.text(f"No data")

                st.write(f"Checking to see if vlan {new_vlan} is configured on {sw}")

                # "Is the new vlan configured on the switch?"
                vlan_on_sw, sq_api_resp_vlan, sq_api_resp_vlan_allvlans = (
                    find_vlan_on_switch(new_vlan, sw)
                )

                if vlan_on_sw:
                    # st.write(sq_api_resp_vlan)
                    req_dict.update({"Is the new vlan configured on the switch?": True})
                else:
                    st.error(f"Device {device_fqdn} cannot be moved.")
                    req_dict.update(
                        {"Is the new vlan configured on the switch?": False}
                    )

                display_requirements(
                    display_header="Status of Checks", req_dict=req_dict
                )

                # Is the vlan working (spanning tree) (Enterprise Version)
                # How is the interface configured? (Enterprise (Version)

                # If all values in req_dict are true the we can proceed with changing the vlan on the interface
                req_values = list(req_dict.values())

                req_val_list = list(set(req_values))

                if len(req_val_list) == 1:
                    if req_val_list[0]:
                        st.success(
                            f"All checks passed! Switch {sw} port {ifname} will be moved to vlan {new_vlan}."
                        )

                        # -------------------------------- CHANGE CONFIGURATION -------------------------------------
                        st.markdown("---")

                        # List of commands to move interface
                        cfg_set = [
                            f"interface {ifname}",
                            f"switchport access vlan {new_vlan}",
                            "shutdown",
                        ]

                        # Generate a device dictionary for Netmiko
                        sw_devdict = create_devobj(sw)

                        # Establish a connection to the device that can be used for sending commands
                        # The conn_netmiko function returns two values, the connection object
                        # and a boolean if the connection was successful
                        sw_conn, login_bool = conn_netmiko(sw_devdict)

                        # The send_netmiko_commands expects a list, even if its just a list with one element
                        # (one show command)
                        st.info(
                            f"Checking current configuration for interface {ifname}"
                        )
                        cmd = [f"show run int {ifname}"]
                        output = send_netmiko_commands(
                            sw_conn, sw, cmd, method="command", cfgmode_bool=False
                        )
                        st.text(output)

                        st.info(
                            f"Pushing vlan change to {sw} {ifname}. Changing vlan from {vlan} to {new_vlan}."
                        )
                        output = send_netmiko_commands(
                            sw_conn,
                            sw,
                            cfg_set,
                            method="config_set",
                            cfgmode_bool=True,
                        )

                        shudown_time_secs = 3
                        cfg_set = [f"interface {ifname}", "no shutdown"]
                        st.info(
                            f"Shutting down port {ifname} for {shudown_time_secs} seconds to force DHCP renewal"
                        )
                        time.sleep(shudown_time_secs)
                        output = send_netmiko_commands(
                            sw_conn,
                            sw,
                            cfg_set,
                            method="config_set",
                            cfgmode_bool=True,
                        )

                        st.info(f"Checking interface configuration after change")
                        cmd = [f"show run int {ifname}"]
                        output = send_netmiko_commands(
                            sw_conn, sw, cmd, method="command", cfgmode_bool=False
                        )
                        st.text(output)

                        # this is only appropriate if DHCP snooping is configured
                        # st.write(f"Checking interface configuration after change")
                        # cmd = [f"show ip dhcp binding | i {new_vlan}"]
                        # output = send_netmiko_commands(
                        #     sw_conn, sw, cmd, method="command", cfgmode_bool=False
                        # )
                        # st.text(output)

                        st.info(f"Checking ARP table for device MAC {mac}")
                        cmd = [f"show ip arp | i {mac_cisco}"]
                        output = send_netmiko_commands(
                            sw_conn, sw, cmd, method="command", cfgmode_bool=False
                        )

                        # Regular expression to check for the ARP entry and get IP and Vlan
                        found_in_arp = False
                        regex = (
                            r"^Internet\s+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+\d+\s+"
                            + f"{mac_cisco}\s+\w+\s+Vlan("
                            + f"{new_vlan}"
                            + ")"
                        )
                        out_lines = output.splitlines()
                        for line in out_lines:
                            search_line = re.search(regex, line)
                            if search_line:
                                st.text(line)
                                found_in_arp = True
                                # Break out of the loop if we get a match so we can use the capture groups later
                                break

                        if found_in_arp:
                            st.success(
                                f":tada: Device {dev_fqdn} has been successfully moved from vlan {vlan} to vlan {new_vlan} and has a new IP of {search_line.groups()[0]} via DHCP!"
                            )
                        else:
                            st.error(f":warning: Something has gone terribly wrong!")

                        st.markdown("---")


# Standard call to the main() function.
if __name__ == "__main__":
    main()
