@echo off

rmdir /S /Q build dist

python setup.py py2exe

