# gollector

Submit domain or IP to Shodan and VirusTotal, pull malicious information, find CS beacons based on JARM signature. 

## Prerequisites

- nmap script to check for CS beacons. Place in $NMAPDIR
  - <https://github.com/whickey-r7/grab_beacon_config/blob/main/grab_beacon_config.nse>
    - Windows: `C:\Program Files (x86)\Nmap\scripts`
    - Linux: `/usr/share/nmap/scripts`
    - MacOS: `/usr/local/share/nmap/scripts`

API Keys are handled through environment variables.

- `VT_API`, `URLSCAN_API`, `SHODAN_API`

- For permanent storage, store in `env` path
  - Windows: Add to system variables or use a PowerShell cmdlet `$env:<API_KEY> = '<value>'`
    - ex. `$env:SHODAN_API = 'apikeyvalues'`
    - check with `$ dir env:`
  - MacOS / Linux: Modify `.bashrc`
    - `$ export API_KEY=VALUE`
    - `$ source ~/.bashrc` 

- For temporary storage, a prompt will appear if the command requires an API key. This method does not persist.

## Help

A `help` command will show available commands. Just run `./gollector help .`

## Run

- MacOS / Linux: `./gollector [command] <ip>`
- Windows: `gollector.exe [command] <input>`
