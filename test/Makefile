CC  = gcc
CXX = g++

all: c_examples cpp_rtti

c_examples:
	$(CC) example.c -o example -g
	$(CC) example2.c -o example2 -g
	arm-linux-gnueabihf-gcc example2.c -o example3 -g
	$(CC) example.c -o example_stripped
	strip --strip-all example_stripped

cpp_rtti: rtti_simple rtti_inherit rtti_diamond

rtti_simple: rtti_simple.cpp
	$(CXX) -std=c++17 -g -frtti -o rtti_simple rtti_simple.cpp

rtti_inherit: rtti_inherit.cpp
	$(CXX) -std=c++17 -g -frtti -o rtti_inherit rtti_inherit.cpp -lm

rtti_diamond: rtti_diamond.cpp
	$(CXX) -std=c++17 -g -frtti -o rtti_diamond rtti_diamond.cpp
