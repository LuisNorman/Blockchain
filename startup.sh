#!/bin/bash
javac -cp "gson-2.8.2.jar" Blockchain.java
sleep 2
gnome-terminal -- sh -c "java -cp \".:gson-2.8.2.jar\" Blockchain 0" &
gnome-terminal -- sh -c "java -cp \".:gson-2.8.2.jar\" Blockchain 1" &
gnome-terminal -- sh -c "java -cp \".:gson-2.8.2.jar\" Blockchain 2" &