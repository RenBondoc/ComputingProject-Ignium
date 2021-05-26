# ComputingProject-Ignium
 
 
# Hyprfire
# Created by Curtin Capstone 2020 Group 23 (Stefan Cyber.)
My Participation in the project consists of creating:
install.py
run.py
hyprfire_app/models.py
hyprfire_app/views.py
hyprfire_app/analysis/CacheHandler.py
hyprfire_app/analysis/ScriptProcessor.py
hyprfire_app/utils/file.py
hyprfire_app/utils/validation.py

### To install:
```
1. Run 'python install.py' if you wish to install all the requirements for the application. (sudo password for user is required for apt-get install and postgres commands)
```

### To run the app
```
1. python run.py
1.1 optional: python run.py (local computer ip address) (whatever port to host django server)
2. travel to [ip]:[port] on your browser
```

### Other directories
```
-logs directory is where logs will be stored at:
    -info.log will store general system information, minor, major, critical incidents
    -warning.log will store minor, major, critical incidents
-pcaps directory is where pcap files should be stored at
```

### Source distribution
```
1) Run python3 setup.py sdist to create a tar.gz of the project. The compressed file will be located in dist directory.
```

# To enable debug-level logging
```
1) Under hyprfire/settings.py, the last section logging describes how to enable debug-level logging.
```

### To change Time-Zone for logs
```
1) Under settings.py, modify TIME_ZONE.
```
