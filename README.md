# 61850-Fuzzing

This repository provides fuzzing scripts for analyzing an IEC 61850 implementation. 

It includes fuzzing scripts for protocols according to the IEC 61850-8-1 standard: SV,Goose and MMS.

The fuzzing scripts are based on the [Boofuzz](https://boofuzz.readthedocs.io/en/stable/) fuzzing framework. 



**Note**: We do not claim that the fuzzing scripts cover the respective protocols in their entirety. 

There may well exist other packet types than those implemented here. 

However, these can easily be supplemented by the method presented in the paper ***"Fuzzing of SCADA Protocols used in Smart Grids"***. 



## Requirements

All requirements are listed in the Requirements.txt file. 

We recommend the use of Python3 (>=3.5).



## Installation

To use the fuzzing scripts, only the requirements have to be installed. 

You can use the command `pip install -r requirements.txt` for this purpose.



## Usage

Every fuzzing script has a help option showing which arguments can and must be specified. 

Nevertheless here is an overview:

--debug , -d = attach debugger (process monitor) to process
--command = command that debugger shall start
--udp = use udp instead of tcp as layer 4 protocol
--dport , -dp = local port of the debugger (default = 26002)
--host = target host address for fuzzing
--port = target port for fuzzing

If you want to use the process-monitor (taken from Boofuzz), start it first as follows

`python3 process_monitor_unix.py` 

It now listens on the local port 26002 by default.

Now start the preferred fuzzing script: (Example MMS)

`python3 mms.py -d -dp 26002 --host 127.0.0.1 --port 102 --command "PATH TO TARGET APPLICATION" `

This should start the fuzzing process.

