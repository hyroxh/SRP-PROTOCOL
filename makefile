# Define the compiler
CC = gcc

# Define directories
INCDIR = include
SRCDIR = src
OBJDIR = obj

# Define libraries and includes
LIBS = -lgmp
LIBARGON2 = libargon2.a
INCLUDES = -I$(INCDIR) -I.

# Define source files
CLIENT_SRCS = $(SRCDIR)/client.c $(SRCDIR)/setup.c $(SRCDIR)/prover.c $(SRCDIR)/mainclient.c
SERVER_SRCS = $(SRCDIR)/server.c $(SRCDIR)/verifier.c $(SRCDIR)/mainserver.c

# Define object files
CLIENT_OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(CLIENT_SRCS))
SERVER_OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SERVER_SRCS))

# Define executables
CLIENT_EXEC = mainclient
SERVER_EXEC = mainserver

# Default target
all: $(CLIENT_EXEC) $(SERVER_EXEC)

# Build client executable
$(CLIENT_EXEC): $(CLIENT_OBJS) $(LIBARGON2)
	$(CC) $(CLIENT_OBJS) $(LIBARGON2) $(LIBS) -o $@

# Build server executable
$(SERVER_EXEC): $(SERVER_OBJS) $(LIBARGON2)
	$(CC) $(SERVER_OBJS) $(LIBARGON2) $(LIBS) -o $@

# Pattern rule for object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(INCLUDES) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJDIR)/*.o $(CLIENT_EXEC) $(SERVER_EXEC)

# Phony targets
.PHONY: all clean
