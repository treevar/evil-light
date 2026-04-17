# Install
Download from https://github.com/treevar/evil-light

# Run Before Building
### install build tools
- apt update
- apt install -y gcc-arm-none-eabi gcc-riscv64-unknown-elf

### get beken sdk
git submodule update --init --recursive sdk/beken_freertos_sdk

### setup virtual python env as system's is managed
- python -m venv venv
- source venv/bin/activate
- pip install -r requirements.txt

# Configuration
- Set C2 Server IP, port, and aes key in src/c2_bulb.h

# Server Setup
- Ensure firewalls allow traffic through
- Enter c2-server folder
- Set aes key and port in server.py
- Run python server.py
- type HELP to see a list of commands

# Building
- make clean
- make OpenBK7238

# Flashing
- First make a backup of the stock firmware in case we need to flash back to it
- ltchiptool flash read -b 115200 -d /dev/ttyUSB0 bk72xxgen2 stock\_firmware\_backup.bin
- Get the latest UART Flash binary for the BK7238 from https://github.com/openshwprojects/OpenBK7231T_App/releases
- ltchiptool flash write -s 0 -b 115200 -f bk72xxgen2 \[BINARY_FILE.bin\]

# Initial Setup
- You can confirm success by checking if an open network starting with 'OpenBeken' appears.
- Connect to the network, access http://192.168.4.1, select configure wifi, and enter your wifi creds
- Save and the bulb should reboot, connecting to the network you entered
- Navigate to http://\[BULB_IP\]/app? and select 'Import' at the top
- Copy & paste the contents of c2-stuff/obk_config.json into the input box
- Press the button under 'Apply Script'
- Restart the bulb

# OTA Update
- Once initial setup is done over the air updates can be done
- Click 'OTA' on the top of the webpage
- Select the .rbl file you got from building
- The bulb should restart in a few seconds
- If there is an error booting then the bulb will boot into the previous image


# Stupid Stuff
- GUI flasher has better success getting a connection, but can't write
- ltchiptool seemingly has no way to erase flash, use the GUI flasher
- When attempting to write using ltchiptool power may have to be switched multiple times and you still might not get a connection. Erasing flash before seems to increase success rate
- Need to call 'make clean' before every build or the binary won't work. It will flash fine, but fail to boot

