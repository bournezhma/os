NAME := $(shell basename $(PWD))
export MODULE := M1
all: $(NAME)-64 $(NAME)-32

test: pstree.c
	@gcc pstree.c -o pstree; ./pstree

include ../Makefile
