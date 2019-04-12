#!/bin/bash
docker run -it --rm -v "${PWD}":/mnt/ --name testing ubuntu bash /mnt/buildSampleExport.sh