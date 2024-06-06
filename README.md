# SRP-PROTOCOL
Password authentication with the SRP protocol in a basic client-server model

In order to compile the programs, you should have argon2 and gmp libraries installed. Please visit https://github.com/P-H-C/phc-winner-argon2 and https://gmplib.org/ for further instuctions.

Don't forget to add argon2.h and libargon2.a to your directory!

To compile the server and the client programs, enter the following command:
$ make

Output files, mainserver and mainclient, are ready for execution.

Brief description of the server programs:
1. server.c -- establishes connection and read/send functions
2. verifier.c -- contains functions for the server to play a verifier role in the authentification part of the protocol.
3. mainserver.c -- works with the database and implements the SRP on the server part.  

Brief description of the client programs:
1. client.c -- establishes connection and read/send functions
2. setup.c -- contains functions for the user to sign up, if previously unsigned.
3. prover.c -- contains function for the user to play a prover role in the authentification part of the protocl
4. mainclient.c -- asks to sign up/log in and implements the SRP on the client part.

