#!/bin/bash

# chmod +x run.sh
# sudo ./run.sh
sudo docker build -t co_v1 .
sudo docker run -it -p 5005:5005 co_v1
