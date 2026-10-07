@echo off
rem Atalho para o lab.ps1 sem esbarrar na ExecutionPolicy do Windows (vale so para este processo).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lab.ps1" %*
