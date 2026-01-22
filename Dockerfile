from python:3.13-trixie

run apt-get update && apt-get upgrade -y
run apt-get install -y make git rustup cmake
run rustup install stable

run pip install angr pwntools

copy . /angrop
workdir /angrop
run pip install -e .
