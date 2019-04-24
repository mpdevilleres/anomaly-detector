# DNS Anomaly Detector
is a pure python cli application that tries to detect anomaly in DNS packets

### Synopsis
a set of different packets for different domains are given as 
    
    more-example.io_20190423_135806073880.packet    
    more-example.io_20190424_064559039448.packet
    example.com_20190423_135806074856.packet

and we are to determine if there's an anomaly in the packets and show them in stdout or logfile like below

    2019-04-24 07:22:36,554 - Thread-1 - ERROR - example.com with IP 172.10.30.171 is an anomaly
    2019-04-24 07:22:36,554 - Thread-3 - ERROR - more-sample.com with IP 164.13.97.82 is an anomaly

## Installation ##
Install python 3.6 or above
 - [Windows](https://www.python.org/downloads/release/python-363/)
 - [Linux](http://docs.python-guide.org/en/latest/starting/install3/linux/#)

Clone this repo
    git clone https://github.com/mpdevilleres/anomaly-detector.git

PS: No other libraries required

## Usage ##
    anomaly_detector.py [-h] [--threads N] [--src source_folder]
                           [--verbose level]
    
    optional arguments:
      -h, --help           show this help message and exit
      --threads N          number of thread (default: 1)
      --src source_folder  source folder for the dns packet files (default:
                           packets)
      --verbose level      verbose level [debug, info, error] (default: error)

# Personal Assumptions and Remarks #
    1. With the given input and without other source of reference, I decided to create a lookup table 
       to validate the preceeding packets by assuming that the first packet with a group of server ips is a good data 
    2. In creating the lookup table I assume that the network are configured with default CIDR refer to below link
        http://www.cse.uconn.edu/~vcb5043/MISC/IP%20Intranet.html
    3. Following the structure given, I am able to create fixtures and provide sample/testing data, the script is named fixture.py
    4. Unittest are also added to validate and ensure the effectivity of the program 
    5. A non threaded version is also included for comparison purposes
    6. I decided to use standard libraries only to avoind complexity in installation 
    7. Threads were implemented in conjunction with Queue this ensure that all the files/tasks are executed and nothing will be forgotten
    8. Also Queue ensure that there's no two task coliding. and makes the application thread safe.    
    9. Overall the task/activity was fun. 
 