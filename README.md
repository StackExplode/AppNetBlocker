# AppNetBlocker
A simple C++ program based on Windows Filtering Platform(WFP) to block a Windows APP from accessing network(except 127.0.0.X) with command line but no need to enable Windows Firewall.

Once you add a rule it will persistantly take effect until you manually remove it.

## Warning

This software is developed as a personal hobby project. No guarantee is provided that it will not damage your computer. It is released under the GPLv3 open source license and is strictly not for commercial use.

## Usage

Your should run the executable with `Administrator permission` and add it to white list of your antivirus softwares.

### 1. Add rule

```
AppNetBlocker.exe add <filePath>
```



### 2. Remove rule

```
AppNetBlocker.exe del <filePath>
```

This will delete all rules related to `filePath`



### 3. List rules

```
AppNetBlocker.exe list <filePath>
```

List all rules related to `filePath`

```
AppNetBlocker.exe list *
```

List all rules added by this software

### 4. Remove rule by Filter ID

```
AppNetBlocker.exe delid <filterID>
```

Delete specific rule by its filterID
