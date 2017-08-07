# Spectator

Regex based source code scanner that uses git enterprise search interface to find potential security vulnerability and
automatically create issues in affected repository.

## Usage

```
python spectator.py scs -h
usage: spectator.py scs [-h] [-t TOKEN] [-r REGEX] [-x TARGETS] [-s SERVER] [-p PROXY] [-o {json,html,notifier}]

optional arguments:
  -h, --help              Show this help message and exit
  -t TOKEN                Access token
  -r REGEX                Regex file to be used
  -x TARGETS              Targets. can be file, or single line. in format [org|user|repo];target
  -s SERVER               Target enterprise server
  -p PROXY                Proxy to tunnel the connection through
  -o {json,html,notifier} Output type
```

```
spectator.py scs -t <token>
spectator.py scs -t <token> -o notifier
```

### Targets

Spectator hcs can read targets from console as string in the format `type;target` for instance if you want to scan
all public repos of specific user for instance 'cucrisis' then use `user:cucrisis`. If target include all repos in an organization then
using something like `user:cucrisis,org:private-org` will do. Also it can read a file where each line is type:target ;) for those picky.

### Server

Is the github enterprise server, default to out server look in the URL thats it

### Proxy

Proxy to use for connection for connection.

### Output

Spectator hcs module can output everything to console in `json` format or it can create each finding as an issue directly on affected repository.

![issue](https://github.com/cucrisis/spectator/blob/master/ref/issue.png?raw=true)

### Regex file
The following are supported entries for each regex.

title: the title of the vulnerability.

overview: Description of the vulnerability.

remediation: Remediation of the vulnerability.

locations: Where to search options ```file, path```

languages: The language to search in ```javascript, python ...etc```

extensions: The file extension to search in ```java, ps1, py```

patterns: The pattern to search for.


```
Sample:
[
  {
    "title": "Weak passwords",
    "overview": "Potential weak password found being used hardcoded or in a config",
    "remediation": "Remove hardcoded password in source code. if its a config change the password to strong password that meets company policy and load it from environment variable when possible",

    "locations":["file"],

    "patterns":[
      "password"
    ]
  }
]
```



## Environment Variables:

SPEC_HCS_TOKEN: Git access token

SPEC_LOG: Output log file, default to ```config/spectator.log```

SPEC_CONFIG: regex file, defaults to ```config/common.regex.json```


