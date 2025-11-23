# Migrate from Pihole v6 to Adguard Home

This tool will take a Teleporter export and convert it into Adguard Home style yaml (or in the case of allowlists / blocklists, Adblock-style rulesets)

## Steps

1. Export your Pihole Teleporter config from settings.
2. Clone this repo.
3. Install PyYAML and dnspython.

   ```bash
   sudo apt install python3-yaml python3-dnspython
   ```
   Or use pip
4. Run the script.

   ```bash
   python3 migrationtool.py pi-hole.xxxxxx.zip
   ```

5. Follow the instructions on screen to update your AdGuardHome.yaml:
   * Stop AdGuardHome with AdGuardHome -s stop
   * Copy the contents of adlists.yaml into AdGuardHome.yaml under 'filters'
   * Copy the contents of clients.yaml into AdGuardHome.yaml under 'clients->persistent'
   * The contents of dns_rewrites.yaml should be copied into AdGuardHome.yaml under the 'rewrites' key.
   * Once done, start up AdGuardHome again. `AdGuardHome -s start`
6. Lastly, you can import your custom allowlists and blocklists by directly pasting them from custome_filters.txt into the "Custom Filtering Rules" screen on AdGuardHome.
