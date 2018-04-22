all: prepare clean

prepare:
	gcc procon1.c -o f.exe -lm
	gcc procon2.c -o t.exe -lm
	./f.exe &
	sleep 0.05
	./t.exe
	
clean:
	rm /tmp/transform

