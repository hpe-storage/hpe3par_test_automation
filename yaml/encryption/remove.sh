#!/bin/sh

kubectl delete pvc --all -n hpe-storage
kubectl delete sc --all

