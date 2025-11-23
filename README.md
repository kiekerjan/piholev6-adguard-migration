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

5. Follow the instructions on screen to update your AdGuardHome.yaml. Once done, start up AdGuardHome again. `AdGuardHome -s start`
6. Lastly, you can import your custom allowlists and blocklists by directly pasting them into the "Custom Filtering Rules" screen on AdGuardHome.
