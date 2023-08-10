OBJ = main.o

EXEWIN = dllninja.exe
MAIN = main.cpp

MINGW = C:\MinGW

LIBSDWIN = -L$(MINGW)\lib
INCSDWIN = -I$(MINGW)\include -I.\include
LIBSWIN = 

BINx32WIN = .\build\x32
BINx64WIN = .\build\x64

install:
	g++ $(MAIN) $(INCSDWIN) $(LIBSDWIN) -o $(EXEWIN) -m32 $(LIBSWIN)
	g++ $(MAIN) $(INCSDWIN) $(LIBSDWIN) -o $(EXEWIN) -m64 $(LIBSWIN)

clean:
	rm dllninja.exe
	rm test32.exe
	rm test64.exe
	
dll:
	g++ -shared -o example.dll example.cpp

test:
	g++ -o test32.exe testexe.cpp -m32
	g++ -o test64.exe testexe.cpp -m64