CCFLAGS = -fPIC
CXXFLAGS = -std=c++11 -nostdlib -fPIC
JAVA_HOME = /usr/lib/jvm/default-java
build: clean
	$(CC) $(CCFLAGS) -c ref10/*.c -Iinclude
	$(CC) $(CCFLAGS) -c nacl/sha512/*.c
	$(CC) $(CCFLAGS) -c nacl/crypto_verify/*.c
	$(CXX) $(CXXFLAGS) -c Curve25519.cpp -I$(JAVA_HOME)/include 
	$(CC) $(CCFLAGS) -o libCurve25519.so -shared *.o
clean:
	rm -fv *.o *.so
test: build
	$(CXX) -fPIC -std=c++11 test_ref10.cpp *.o -o test_ref10
all: build
