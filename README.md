# kauma-labwork

Uni project > Response program to process & solve assignments given by an api (T3INF9004: Cryptanalysis und Method-Audit).

usage: ```main.py [-h] [-v] [-p PROCESS_COUNT] [--debug] endpoint client_id labwork_id```

positional arguments:
- ```endpoint```          labwork endpoint, for example 'https://example.com/endpoint'
- ```client_id```         client uuid, for example 'cafebabe-0000-0000-0000-000000000000'
- ```labwork_id```        labwork identifier, for example 'labwork01'

options:
- ```-h```, ```--help```        show help message and exit
- ```-v```, ```--verbose```     increase verbosity (up to 3 times)
- ```-p PROCESS_COUNT```        number of processes to use for parallel processing (same case type)
- ```--debug```                 enable debug mode
