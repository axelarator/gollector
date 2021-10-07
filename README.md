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

- Commands:
  - search [Submit IP to shodan with ability to pivot on JARM signature]
  - rdns [Reverse DNS lookup]
  - whois [Standard whois lookup]
  - unfurl [Unfurl an address to break it up into components]
  - bracket : unbracket [Modifies a url to avoid accidental clicks : Does the opposite]
  - urlencode : urldecode [Converts URL to UTF-8 format : Converts UTF-8 back to plaintext]
  - b64encode : b64decode [Simple base64 encode : decode]
  - vt [Submit a url/hash/ip to VirusTotal]

## Run

- MacOS / Linux: `./gollector search <ip>`
- Windows: `gollector.exe search <ip>`
