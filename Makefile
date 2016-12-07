.PHONY: default all clean

default: all

all:
	javac -cp jnetpcap.jar ids.java
# java -cp .:jnetpcap.jar -Djava.library.path=. ids 

clean:
	-rm -f ids
