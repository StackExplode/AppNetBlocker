# AppNetBlocker
A simple C++ program to block a windows APP from accessing network(except 127.0.0.X) with command line.

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



### 4. Remove rule by Filter ID

```
AppNetBlocker.exe delid <filterID>
```

Delete specific rule by its filterID
