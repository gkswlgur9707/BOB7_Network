all: sum_test

sum.o: sum.h sum.cpp
	g++ -c -o sum.o sum.cpp

main.o: sum.h main.cpp
	g++ -c -o main.o main.cpp

sum_test: main.o sum.o
	g++ -o sum_test main.o sum.o

clean: 
	rm -f *.o
	rm -f sum_test


