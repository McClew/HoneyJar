import os
import sys
import time
import subprocess
from colorama import Fore, Back, Style
import configparser
import socket
import asyncio
from typing import TextIO
import logging
from logging.handlers import SysLogHandler

CONFIG_FILE = "honeypot_config.ini"
CONFIG_REQUIRED_SECTIONS = {
	'Syslog': ['host', 'port'],
	'Honeypot': ['listen_pairs']
}

SERVICE_BANNERS = {
    "SSH": b"SSH-2.0-OpenSSH_8.9p1\r\n", 
    "FTP": b"220 Microsoft FTP Service\r\n", 
    "Telnet": b"Welcome to the Telnet Server.\r\n",
    "HTTP": b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n",
    "CustomBanner": b"220 Honeypot Service V1.0 Ready\r\n",
    "MYSQL_HANDSHAKE": (
        b'\x4a\x00\x00\x00\x0a'								# Packet Header (4 bytes) and Protocol Version (1 byte, 0x0a)
        b'8.0.26-log\x00'									# Server Version String (Spoofed version)
        b'\x01\x00\x00\x00'									# Connection ID
        b'!\x13\x12\x0b\x00\x08\t\x03'						# Salt/Auth Data Part 1 (8 bytes)
        b'\x00\xff\xf7\x08\x02\x00\x00\x00'					# Server Capabilities/Status
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'	# Reserved/Padding
        b'P\x04I\x16\x1a\x17P\x01\x18\x01\x0f\x03'			# Salt/Auth Data Part 2 (12 bytes)
        b'\x00'												# Auth Plugin name
    ),
}

app_config = {}

def display_banner():
	print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
	print(Fore.YELLOW + "|          HONEYPOT          |" + Style.RESET_ALL)
	print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)

class Utility:
	def __init__(self):
		pass

	@staticmethod
	def clear_cli():
		if sys.platform == "linux" or sys.platform == "linux2":
			subprocess.run(["clear"])
		elif sys.platform == "win32":
			os.system("cls")

class Config:
	def __init__(self):
		pass

	@staticmethod
	def load_config():
		print(Fore.BLUE + "[INF]" + Style.BRIGHT + " Loading configuration..." + Style.RESET_ALL)

		config = configparser.ConfigParser()

		# Load configuration file
		if not config.read(CONFIG_FILE):
			print(Fore.RED + "[ERR]" + " Configuration file not found!" + Style.RESET_ALL)
			sys.exit(Fore.BLUE + "[INF]" + Style.BRIGHT + " Exiting application." + Style.RESET_ALL)
		
		print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Configuration loaded from {CONFIG_FILE}." + Style.RESET_ALL)
		
		final_config = {}

		# Error check config
		try:
			for section, keys in CONFIG_REQUIRED_SECTIONS.items():
				
				# Check for missing section
				if section not in config:
					raise KeyError(f"Required section '[{section}]' is missing." + Style.RESET_ALL)

				section_data = config[section]
				
				# Check for missing keys
				for key in keys:
					# The variable for the flattened key
					config_key_flat = f'{section.lower()}_{key}'

					if key not in section_data:
						raise KeyError(f"Required key '{key}' is missing in section '[{section}]'.")

					value = section_data[key]

					# Custom handling for listen_pairs
					if key == 'listen_pairs':
						pairs = []
						
						# Split by the pair separator (;) and remove whitespace
						raw_pairs = [p.strip() for p in value.split(';') if p.strip()]

						for raw_pair in raw_pairs:
							# Split each pair by the separator (:)
							parts = [part.strip() for part in raw_pair.split(':')]

							if len(parts) != 3:
								raise ValueError(f"Invalid format in listen_pairs: '{raw_pair}'. Expected PORT:SERVICE:PROTOCOL.")

							port_str, service_name, protocol_str = parts

							try:
								port = int(port_str)
							except ValueError:
								raise ValueError(f"Port '{port_str}' is not a valid integer.")

							protocol = protocol_str.upper()
							if protocol not in ['TCP', 'UDP']:
								raise ValueError(f"Protocol '{protocol_str}' is invalid. Must be TCP or UDP.")

							if service_name not in SERVICE_BANNERS:
								raise ValueError(f"Service '{service_name}' has no defined banner in SERVICE_BANNERS dictionary.")

							# Add the parsed pair: [(port, service, protocol), ...]
							pairs.append((port, service_name, protocol))

						final_config[config_key_flat] = pairs

					else:
						final_config[config_key_flat] = value

		except (KeyError, ValueError) as error:
			# Catch both structural (KeyError) and parsing (ValueError) issues
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Configuration validation error: {error}")
			sys.exit(Fore.BLUE + "[INF]" + Style.BRIGHT + " Exiting application due to configuration issues.")

		return final_config

	@staticmethod
	def edit_config():
		Utility.clear_cli()
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|    CONFIGURATION EDITOR    |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		
		try:
			app_config = Config.load_config()
		except SystemExit:
			return

		print("")

		new_settings = {}

		for section, keys in CONFIG_REQUIRED_SECTIONS.items():
			print(Style.BRIGHT + f"[{section}]" + Style.RESET_ALL)

			for key in keys:
				config_key = section.lower() + "_" + key.lower()
				
				# Custom handling for listen_pairs
				if key == 'listen_pairs':
					current_value = "; ".join([f"{p}:{s}:{pr}" for p, s, pr in app_config[config_key]])
					print(f"{section} {key} (Format: PORT:SERVICE:PROTOCOL;...): {current_value}")
				else:
					current_value = app_config[config_key]
					print(f"{section} {key}: {current_value}")

				if input("Modify value? (y/n): ").lower() == "y":
					if key == 'listen_pairs':
						new_value = input(f"{section} {key} [ENTER NEW STRING]: ")
					else:
						new_value = input(f"{section} {key}: ")
						
					new_settings[config_key] = new_value
				else:
					if key == 'listen_pairs':
						new_settings[config_key] = current_value
					else:
						new_settings[config_key] = current_value

				print("")

		if input("Save changes? (y/n): ").lower() == 'y':
			print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + " Configuration saved.")
			Config.save_config(new_settings)
		else:
			print(Fore.BLUE + "[INF]" + Style.RESET_ALL + " Configuration edit cancelled.")
			return None

		# Clear and return to main menu
		Utility.clear_cli()

	@staticmethod
	def save_config(config_data):
		config = configparser.ConfigParser()
	
		# Re-structure the flat dictionary into sections for saving
		save_sections = {}

		for key, value in config_data.items():
			section, name = key.split('_', 1)
			section = section.title()

			# Custom handling for listen_pairs during saving
			if name == 'listen_pairs':
				if isinstance(value, list):
					final_value = "; ".join([f"{p}:{s}:{pr}" for p, s, pr in value])
				else:
					final_value = str(value)
			else:
				final_value = str(value)

			if section not in save_sections:
				save_sections[section] = {}

			# Store the final string value for the INI file
			save_sections[section][name] = final_value

		for section_name, section_dict in save_sections.items():
			config[section_name] = section_dict

		try:
			with open(CONFIG_FILE, 'w') as f:
				config.write(f)
			return True
		except IOError:
			return False

def startup():
	display_banner()
	Utility.clear_cli()

def view_banner(banner_name, banner_data):
	Utility.clear_cli()
	print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
	print(Fore.YELLOW + "|  AVAILABLE SERVICE BANNERS   |" + Style.RESET_ALL)
	print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
	print(Fore.YELLOW + f">  VIEWING BANNER: {banner_name:<11}" + Style.RESET_ALL)
	try:
		decoded_banner = banner_data.decode('utf-8').strip().replace('\r\n', ' [CRLF] ')
		print(Fore.GREEN + Style.BRIGHT + "Type: Text/ASCII" + Style.RESET_ALL)
		print("-" * 40)
		print(decoded_banner)
		print("-" * 40)
		
	except UnicodeDecodeError:
		print(Fore.RED + Style.BRIGHT + "Type: Binary/Protocol Handshake" + Style.RESET_ALL)
		print(Fore.RED + "WARNING: Cannot display binary data directly as text." + Style.RESET_ALL)
		print("-" * 40)
		print("Raw Hexadecimal Data:")

		print(banner_data.hex())
		print("-" * 40)
		
	input("\nPress Enter to return to the Banner List...")

def banner_menu():
	banner_names = list(SERVICE_BANNERS.keys())
	
	while True:
		Utility.clear_cli()
		print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|  AVAILABLE SERVICE BANNERS   |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
		
		for i, name in enumerate(banner_names):
			print(f"{i + 1}. {name}")
			
		print("-" * 30)
		print("0. Return to Main Menu")
		print("-" * 30)
		
		choice = input("Select a banner number (1-{}) or 0: ".format(len(banner_names))).strip()
		
		try:
			choice_index = int(choice)
			
			if choice_index == 0:
				Utility.clear_cli()
				return

			elif 1 <= choice_index <= len(banner_names):
				selected_name = banner_names[choice_index - 1]
				selected_data = SERVICE_BANNERS[selected_name]
				
				view_banner(selected_name, selected_data) # Call the viewer function
				
			else:
				print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Invalid number selected.")
				time.sleep(1)
				
		except ValueError:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Invalid input. Please enter a number.")
			time.sleep(1)

def setup_syslog_logger(config):
	global honeypot_logger
	
	SYSLOG_HOST = config['syslog_host']
	SYSLOG_PORT = int(config['syslog_port'])
	
	logger = logging.getLogger('HoneypotLogger')
	logger.setLevel(logging.INFO)
	
	# Prevent logging messages from duplicating via the root handler
	logger.propagate = False 

	# Create SysLogHandler
	try:
		handler = SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT), facility=SysLogHandler.LOG_LOCAL1, socktype=socket.SOCK_DGRAM) # Use UDP for Syslog
		
		formatter = logging.Formatter('%(name)s: %(message)s')
		handler.setFormatter(formatter)
		logger.addHandler(handler)
		
		honeypot_logger = logger # Assign to global variable
		print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Syslog logging initialized at {SYSLOG_HOST}:{SYSLOG_PORT}.")
		return logger
		
	except Exception as error:
		print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Failed to set up Syslog logger: {error}")
		return None # Return None if setup fails

async def handle_tcp_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
	# Handles a single zero-interaction TCP connection
	addr = writer.get_extra_info('peername')
	attacker_ip, attacker_port = addr[0], addr[1]
	target_port = writer.get_extra_info('sockname')[1]
	
	# Determine which service name was used to launch this listener
	banner_data = None
	for _, service_name, protocol in app_config['honeypot_listen_pairs']:
		if protocol == 'TCP' and target_port == _:
			banner_data = SERVICE_BANNERS.get(service_name)
			break

	log_message = f"TCP connection received. TargetPort={target_port} SourceIP={attacker_ip}"
	captured_data_log = ""

	if banner_data:
		try:
			# Send the service banner
			writer.write(banner_data)
			await writer.drain() 
			
			# Wait briefly for a response (e.g., username/password)
			data = await asyncio.wait_for(reader.read(1024), timeout=1.5) 
			
			if data:
				captured_data_log = f" CapturedData='{data.decode(errors='ignore').strip()}'"

		except asyncio.TimeoutError:
			captured_data_log = " CapturedData='None (Timeout)'"

		except ConnectionResetError:
			captured_data_log = " ConnectionReset='True'"
            
		except UnicodeDecodeError:
			captured_data_log = " CapturedData='Binary/Undecodable Bytes'"
	
	# Log the event
	if honeypot_logger:
		honeypot_logger.info(log_message + captured_data_log, extra={'target_port': target_port, 'source_ip': attacker_ip})
	else:
		print(Fore.RED + "[LOG_ERR]" + Style.RESET_ALL + log_message + captured_data_log)
		
	# Immediately close the connection
	writer.close()
	await writer.wait_closed()

class UdpHoneypot(asyncio.DatagramProtocol):
    def __init__(self, target_port, service_name):
        # Store information about this specific listener instance
        self.target_port = target_port
        self.service_name = service_name

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        attacker_ip, attacker_port = addr
        
        log_message = f"UDP datagram received. TargetPort={self.target_port} SourceIP={attacker_ip}"
        
        try:
            captured_data_log = f" CapturedData='{data.decode(errors='ignore').strip()}'"
        except UnicodeDecodeError:
            captured_data_log = f" CapturedData='Binary/Undecodable Bytes'"

        if honeypot_logger:
            honeypot_logger.info(log_message + captured_data_log)
        else:
            print(Fore.RED + "[LOG_ERR]" + Style.RESET_ALL + log_message + captured_data_log)

async def start_multiple_listeners(listen_pairs):
	# Launches concurrent TCP and UDP listeners
	tasks = []
	
	for port, service, protocol in listen_pairs:
		try:
			if protocol == 'TCP':
				# Start a TCP Server
				server = await asyncio.start_server(
					handle_tcp_connection, '0.0.0.0', port
				)
				tasks.append(server.serve_forever())
				print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Listening on TCP port {port} (Service: {service})")
				
			elif protocol == 'UDP':
				# Start a UDP Listener
				transport, protocol_instance = await asyncio.get_event_loop().create_datagram_endpoint(
					lambda: UdpHoneypot(port, service), local_addr=('0.0.0.0', port)
				)
				# Store the transport handle to keep the task alive
				tasks.append(transport.close()) 
				print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Listening on UDP port {port} (Service: {service})")

		except OSError as error:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Could not bind {protocol} port {port}: {error.strerror}")

	if not tasks:
		print(Fore.RED + "[ERR]" + Style.RESET_ALL + " No honeypots successfully started.")
		return

	# Keep the main loop running until interrupted
	await asyncio.gather(*tasks)

def start_honeypot():
	global app_config	
	listen_pairs = app_config.get('honeypot_listen_pairs')
	
	if not listen_pairs:
		print(Fore.RED + "[ERR]" + Style.RESET_ALL + " No listening pairs configured.")
		return

	# Setup logging
	setup_syslog_logger(app_config) 
	
	print(Fore.CYAN + "\n[RUN]" + Style.RESET_ALL + " All honeypots active. Press Ctrl+C to stop.")
	
	try:
		# Start the async event loop
		asyncio.run(start_multiple_listeners(listen_pairs))
		
	except KeyboardInterrupt:
		print(Fore.YELLOW + "\n[STOP]" + Style.RESET_ALL + " All honeypots stopped by user.")
	except Exception as error:
		print(Fore.RED + "[CRIT]" + Style.RESET_ALL + f" An unhandled error occurred during runtime: {error}")

def main_menu():
	global app_config
	while True:
		try:
			app_config = Config.load_config()
		except SystemExit:
			return

		print("\n" + Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|          HONEYPOT          |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		print(f"Syslog Target: {app_config['syslog_host']}:{app_config['syslog_port']}")
		print("Honeyed Ports: " + ", ".join([f"{port}:{service}:{protocol}" for port, service, protocol in app_config['honeypot_listen_pairs']]))
		print("")
		print("-" * 30)
		print("1. Start Honeypot")
		print("2. Edit Configuration")
		print("3. View Services")
		print("4. Exit Application")
		print("-" * 30)

		choice = input("Select an option (1-4): ").strip()

		if choice == '1':
			start_honeypot()
		elif choice == '2':
			Config.edit_config()
		elif choice == '3':
			banner_menu()
		elif choice == '4':
			print(Fore.BLUE + "[INF]" + Style.BRIGHT + " Shutting down." + Style.RESET_ALL)
			break
		else:
			Utility.clear_cli()
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Invalid choice. Please select 1, 2, or 3." + Style.RESET_ALL)

if __name__ == "__main__":
	Utility.clear_cli()
	startup()
	main_menu()