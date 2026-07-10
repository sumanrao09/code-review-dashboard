import os


def run(cmd):
    os.system("echo " + cmd)  # command injection smell
