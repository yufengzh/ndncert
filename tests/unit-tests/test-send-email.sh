#!/bin/sh

RECEIVER=$1
SECRET=$2

MESSAGE=$RECEIVER" "$SECRET

echo $MESSAGE > tmp.txt
