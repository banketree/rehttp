RE=../re-0.4.2

INCS=-I$(RE)/include
LIBS=-L$(RE) -lre
CFLAGS=-DHAVE_INET6

http: http.c cli.c auth.c
	cc http.c cli.c auth.c -o http $(LIBS) $(INCS) $(CFLAGS)
