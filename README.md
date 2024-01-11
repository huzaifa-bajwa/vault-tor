# vault-tor

## Building for Linux

Run `make SGX=1` in the directory.

## Running the server

gramine-sgx ./python scripts/server.py

## Running the ssh enabled terminal or the tor enabled terminal

gramine-sgx ./bash 
gramine-sgx ./bash -c "The command you want to execute"
