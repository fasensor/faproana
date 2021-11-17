# proana

FaPro elasticsearch logs ana project

## Installation

Download from https://github.com/ntestoc/proana

## Usage

```shell 
# specify es server
export ES_HOST='{:hosts ["http://your-es-server:9200"]}'

## if your elasticsearch use basic auth 
export ES_HOST='{:hosts ["http://your-es-server:9200"]
                 :http-client {:basic-auth {:user "elastic"
                                            :password "yourpassword"}}}'

# specify top count, default 10
export TOP_NUMBER=10

# specify TOTAL_FAPRO_HOSTS=your-fapro-node-count, default 33
export TOTAL_FAPRO_HOSTS=33

java -jar proana.jar  -s start-date 
```

## build from source 
clojure -T:build uber

## License

Copyright © 2021 fapro

Distributed under the Eclipse Public License version 1.0.
