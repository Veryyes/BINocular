from ghidra.framework import Application
from java.lang import System


def main():
    version = Application.getApplicationVersion()
    System.out.println("Ghidra Version: {}".format(version))


main()
