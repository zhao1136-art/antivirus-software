@echo off
F:\Python314\python.exe -c "import tkinter; print('tkinter OK:', tkinter.__file__)" 2>&1
F:\Python314\python.exe -c "import tkinter.ttk; print('ttk OK')" 2>&1
pause