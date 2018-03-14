# newrelic-alerts-report
Python script for generating a list of New Relic alert policies and conditions.

required packages: requests

usage: alertsReport.py [-h] [-o OUTPUTFILE] [-p] [-i] [-lp LIMITPOLICIES]
                       [-lc LIMITCONDITIONS] [-id] [-d {info,debug}]
                       apikey

Query a New Relic RPM for all alert policy conditions and their entities

positional arguments:
  apikey                New Relic RPM Admin API Key

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        File name to wrtie report to (default=output.csv)
  -p, --printoutput     Print output file to screen in addition to file
  -i, --includeservers  Include results for New Relic Servers (soon to be
                        deprecated)
  -lp LIMITPOLICIES, --limitpolicies LIMITPOLICIES
                        Limit the number of policies returned
  -lc LIMITCONDITIONS, --limitconditions LIMITCONDITIONS
                        Limit the number of conditions returned per policy
  -id, --ignoredisabled
                        Do not include disabled conditions in the report
  -d {info,debug}, --debuglevel {info,debug}
                        Set the stdout debug level
