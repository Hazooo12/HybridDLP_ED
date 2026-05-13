@echo off
:: Launcher wrapper for DLP Native Messaging Host.
:: Chrome requires an executable path in native_host.json.
:: This batch file allows Chrome to launch native_host.py via Python.
python "%~dp0native_host.py"
