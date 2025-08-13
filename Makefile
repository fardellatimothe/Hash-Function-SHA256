# Nom de l'exécutable
TARGET = sha256

# Compilateur et options
CC = gcc
CFLAGS = -Wall -Wextra -std=c11

# Fichiers sources et objets
SRC = main.c sha256.c test_unitaire.c
OBJ = $(SRC:.c=.o)

# Règle par défaut
all: $(TARGET)

# Compilation de l'exécutable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compilation des fichiers .c en .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers compilés
clean:
	rm -f $(OBJ) $(TARGET)

# Nettoyage complet
mrproper: clean
	rm -f $(TARGET)
