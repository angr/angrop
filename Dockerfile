from python:3.13-bookworm

run apt-get update && apt-get upgrade -y
run pip install --upgrade pip 

run apt-get install -y make binutils-riscv64-linux-gnu git

# setup python dependencies
run pip install cffi pwntools unicorn==2.0.1.post1 protobuf==5.28.2
run pip install --upgrade setuptools

run git clone --depth 1 -b wip/riscv https://github.com/angr/archinfo /archinfo
workdir /archinfo
run pip install -e .
run pip install pyvex==9.2.139 cle==9.2.139 claripy==9.2.139
run git clone --depth 1 -b wip/riscv https://github.com/angr/angr /angr
workdir /angr
run sed -i 's/9.2.153.dev0/9.2.139/' angr/__init__.py
run sed -i 's/9.2.153.dev0/9.2.139/' ./pyproject.toml
run pip install --no-build-isolation -e .

# install angrop
copy . /angrop
workdir /angrop
run pip install -e .
run pip install ailment==9.2.153

